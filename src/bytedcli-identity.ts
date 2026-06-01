/**
 * bytedcli 身份注入（多租户沙盒）——JWT-based。
 *
 * 让容器内能用真人身份跑 bytedcli / git 拉 code.byted.org。
 *
 * ★ 关键约束（2026-06-01 实测）：bytedcli 凭证文件用机器级 device key（macOS
 *   keychain）加密，**裸 mount 凭证文件进 linux 容器解不开**（authenticated:False）。
 *   唯一活路 = JWT 注入：JWT 自包含不依赖 device key。
 *
 * 架构：
 *   1. host 持已认证凭证（operator 默认 HOME / per-user sandbox HOME），host 有 device
 *      key 能解密 → 同步 `get-codebase-jwt-token` + `get-bytecloud-jwt-token` 拿 fresh JWT
 *   2. 在 per-user mount 目录生成：
 *      - .git-credentials（`https://x-jwt-token:<codebase-jwt>@code.byted.org`）+ .gitconfig（helper=store）→ git 拉代码
 *      - data/jwt_override.cloud.<host>.json（bytecloud JWT）→ 容器内 bytedcli 命令
 *   3. mount 进容器；JWT 短效，每轮 spawn 重新生成
 *
 * 全部行为由 BYTEDCLI_INJECT=true 门控；未开启时不挂载，容器行为不变。
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  fetchCredentialJwts,
  getUserBytedcliSandbox,
  hasAuthedSandbox,
} from './bytedcli-auth.js';
import { getUserById } from './db.js';
import { logger } from './logger.js';

/** 容器内 bytedcli 数据目录（node 用户），放 jwt_override 文件。 */
export const CONTAINER_BYTEDCLI_DATA = '/home/node/.local/share/bytedcli/data';
/** 容器内 .gitconfig（node 用户）。 */
export const CONTAINER_GITCONFIG = '/home/node/.gitconfig';
/** 容器内 .git-credentials（node 用户，helper=store 读它）。 */
export const CONTAINER_GIT_CREDENTIALS = '/home/node/.git-credentials';

/** 是否开启 bytedcli 身份注入。关闭时容器完全不挂载 bytedcli 相关卷。 */
export function isBytedcliInjectEnabled(): boolean {
  return process.env.BYTEDCLI_INJECT === 'true';
}

/**
 * 是否开启 per-user SSO 模式（authed user 用自己 sandbox，pending/expired 不挂）。
 * 关 = 用 operator 单身份（demo / D fallback）。
 */
export function isPerUserModeEnabled(): boolean {
  return process.env.BYTEDCLI_PER_USER === 'true';
}

/**
 * 从 group 推导真正归属的 ownerId（修 created_by bug）：
 *   member home group folder=`home-<userId>` → 解析 memberId；否则 fallback created_by。
 * 背景见 git log b7cd70a 段：IM-bound is_home=0 兄弟行 created_by=admin，会让所有 member
 * 共享 operator 身份。folder 前缀解析绕开 DB 歧义。
 */
export function getEffectiveOwnerId(group: {
  folder: string;
  created_by?: string;
}): string | undefined {
  if (group.folder.startsWith('home-')) {
    const candidate = group.folder.slice('home-'.length);
    if (candidate) return candidate;
  }
  return group.created_by;
}

/**
 * operator 凭证来源 HOME（非 per-user 模式 / per-user status=none 时用）。
 * 默认 os.homedir()（部署 happyclaw 的人本人的 ByteCloud Auth 登录态）。
 */
function getOperatorSourceHome(): string {
  return process.env.BYTEDCLI_SOURCE_HOME || os.homedir();
}

/** code.byted.org git credential（.git-credentials 单行）。 */
function buildGitCredentials(codebaseJwt: string): string {
  const pat = process.env.CODEBASE_PAT;
  if (pat) {
    return `https://x-access-token:${pat}@code.byted.org\n`;
  }
  return `https://x-jwt-token:${codebaseJwt}@code.byted.org\n`;
}

/** .gitconfig：credential.helper=store（从 .git-credentials 读凭证）。 */
function buildGitconfig(): string {
  return [
    '[credential]',
    '\thelper = store',
    '',
  ].join('\n');
}

export interface BytedcliIdentityMounts {
  /** per-user data 目录（含 jwt_override）→ CONTAINER_BYTEDCLI_DATA（rw）。 */
  hostDataDir: string;
  /** .git-credentials → CONTAINER_GIT_CREDENTIALS（ro）。 */
  hostGitCredentials: string;
  /** .gitconfig → CONTAINER_GITCONFIG（ro）。 */
  hostGitconfig: string;
}

/**
 * 解析凭证来源 HOME：
 *   per-user 模式：authed+sandbox 存在 → sandbox HOME；pending/expired → null（强制 /login）；
 *                  none → operator HOME（首次使用赠默认身份，UX 平滑）
 *   非 per-user：operator HOME
 * @returns sourceHome 或 null（不应注入）
 */
function resolveSourceHome(ownerId: string, dataDir: string): string | null {
  if (!isPerUserModeEnabled()) return getOperatorSourceHome();

  const user = getUserById(ownerId);
  if (!user) {
    logger.warn({ ownerId }, 'bytedcli-identity: per-user mode but user row not found, skip');
    return null;
  }
  const status = user.bytedcli_auth_status;
  if (status === 'authed') {
    if (hasAuthedSandbox(ownerId, dataDir)) {
      return getUserBytedcliSandbox(ownerId, dataDir);
    }
    logger.warn(
      { ownerId },
      'bytedcli-identity: status=authed but sandbox missing — falling back to operator',
    );
    return getOperatorSourceHome();
  }
  if (status === 'pending' || status === 'expired') {
    logger.info(
      { ownerId, status },
      'bytedcli-identity: per-user pending/expired — skip mount, user must /login',
    );
    return null;
  }
  // none → operator 兜底
  return getOperatorSourceHome();
}

/**
 * 确保容器 bytedcli 身份就位（JWT-based），返回挂载路径。
 * 每轮 spawn 调一次：host 同步拿 fresh JWT → 写 .git-credentials + jwt_override → mount。
 *
 * @param ownerId  happyclaw user id（经 getEffectiveOwnerId 解析）
 * @param dataDir  happyclaw DATA_DIR
 * @returns 挂载路径，或 null（未开启 / 源未认证 / per-user pending）
 */
export function ensureBytedcliIdentity(
  ownerId: string,
  dataDir: string,
): BytedcliIdentityMounts | null {
  if (!isBytedcliInjectEnabled()) return null;
  if (!ownerId) return null;

  const sourceHome = resolveSourceHome(ownerId, dataDir);
  if (!sourceHome) return null;

  // CODEBASE_PAT 模式：不依赖 host 认证，直接用 PAT 拼 .git-credentials（仍生成空 data 目录）。
  const pat = process.env.CODEBASE_PAT;
  let codebaseJwt = '';
  let bytecloudJwt = '';
  let cloudHost = 'https://cloud.bytedance.net';
  if (!pat) {
    const jwts = fetchCredentialJwts(sourceHome);
    if (!jwts) {
      logger.warn(
        { ownerId, sourceHome },
        'bytedcli-identity: fetchCredentialJwts failed (source not authed), skip mount',
      );
      return null;
    }
    codebaseJwt = jwts.codebaseJwt;
    bytecloudJwt = jwts.bytecloudJwt;
    cloudHost = jwts.cloudHost;
  }

  const mountRoot = path.join(dataDir, 'config', 'user-cli', ownerId, 'bytedcli-mount');
  const mountDataDir = path.join(mountRoot, 'data');
  const gitCredentials = path.join(mountRoot, '.git-credentials');
  const gitconfig = path.join(mountRoot, '.gitconfig');

  try {
    fs.mkdirSync(mountDataDir, { recursive: true });
    // git 凭证（每轮 fresh）
    fs.writeFileSync(gitCredentials, buildGitCredentials(codebaseJwt), { mode: 0o644 });
    fs.writeFileSync(gitconfig, buildGitconfig(), { mode: 0o644 });
    // bytecloud JWT override（供容器内 bytedcli 命令；git 不需要它）
    if (bytecloudJwt) {
      const host = cloudHost.replace(/^https?:\/\//, '');
      const overrideFile = path.join(mountDataDir, `jwt_override.${host}.json`);
      fs.writeFileSync(
        overrideFile,
        JSON.stringify({
          token: bytecloudJwt,
          host: cloudHost,
          saved_at: new Date().toISOString(),
        }) + '\n',
        { mode: 0o644 },
      );
    }
  } catch (err) {
    logger.warn({ ownerId, err }, 'bytedcli-identity: failed to write credential files');
    return null;
  }

  logger.info(
    { ownerId, sourceHome, mode: pat ? 'pat' : 'jwt' },
    'bytedcli-identity: credentials prepared (git + jwt_override)',
  );

  return {
    hostDataDir: mountDataDir,
    hostGitCredentials: gitCredentials,
    hostGitconfig: gitconfig,
  };
}
