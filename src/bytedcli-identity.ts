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
  ensureCodebasePat,
  getUserBytedcliSandbox,
  hasAuthedSandbox,
} from './bytedcli-auth.js';
import { getUserById, getUserCodebasePat, setUserCodebasePat } from './db.js';
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

/** code.byted.org git credential 单行（PAT 用 x-access-token，JWT 用 x-jwt-token）。 */
function gitCredLine(username: string, secret: string): string {
  return `https://${username}:${secret}@code.byted.org\n`;
}

/**
 * .gitconfig：credential.helper=store 指向容器内 rw data 目录下的 .git-credentials。
 * 用 --file 显式指向 rw 路径（非默认 ~/.git-credentials），让 git store 能写回，
 * 避免 ro 单文件 mount 的 "unable to write credential store: Device busy" warning。
 */
function buildGitconfig(): string {
  return [
    '[credential]',
    `\thelper = store --file=${CONTAINER_BYTEDCLI_DATA}/.git-credentials`,
    '',
  ].join('\n');
}

export interface BytedcliIdentityMounts {
  /** per-user data 目录（含 jwt_override + .git-credentials）→ CONTAINER_BYTEDCLI_DATA（rw）。 */
  hostDataDir: string;
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

  // 凭证优先级：① CODEBASE_PAT env（operator 显式 PAT）② per-user 自动 PAT（方案 C）
  //            ③ JWT 兜底（operator non-per-user / per-user 关）
  let credLine: string;
  let bytecloudJwt = '';
  let cloudHost = 'https://cloud.bytedance.net';

  const envPat = process.env.CODEBASE_PAT;
  if (envPat) {
    credLine = gitCredLine('x-access-token', envPat);
  } else if (isPerUserModeEnabled()) {
    // per-user：自助 create/复用 PAT（长效 90 天，存 DB user_secrets）
    const existing = getUserCodebasePat(ownerId);
    const pat = ensureCodebasePat(sourceHome, ownerId, existing);
    if (!pat) {
      logger.warn({ ownerId, sourceHome }, 'bytedcli-identity: ensureCodebasePat failed, skip mount');
      return null;
    }
    if (!existing || existing.token !== pat.token) setUserCodebasePat(ownerId, pat);
    credLine = gitCredLine('x-access-token', pat.token);
    // 顺带 bytecloud JWT（容器内 bytedcli 命令的 jwt_override，best-effort）
    const jwts = fetchCredentialJwts(sourceHome);
    if (jwts) {
      bytecloudJwt = jwts.bytecloudJwt;
      cloudHost = jwts.cloudHost;
    }
  } else {
    const jwts = fetchCredentialJwts(sourceHome);
    if (!jwts) {
      logger.warn(
        { ownerId, sourceHome },
        'bytedcli-identity: fetchCredentialJwts failed (source not authed), skip mount',
      );
      return null;
    }
    credLine = gitCredLine('x-jwt-token', jwts.codebaseJwt);
    bytecloudJwt = jwts.bytecloudJwt;
    cloudHost = jwts.cloudHost;
  }

  const mountRoot = path.join(dataDir, 'config', 'user-cli', ownerId, 'bytedcli-mount');
  const mountDataDir = path.join(mountRoot, 'data');
  // .git-credentials 放 rw 的 data 目录内（gitconfig helper --file 指向它），git store 可写回。
  const gitCredentials = path.join(mountDataDir, '.git-credentials');
  const gitconfig = path.join(mountRoot, '.gitconfig');

  try {
    fs.mkdirSync(mountDataDir, { recursive: true });
    // git 凭证（PAT 长效复用 / JWT 每轮 fresh）
    fs.writeFileSync(gitCredentials, credLine, { mode: 0o644 });
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

  const credMode = envPat ? 'env-pat' : isPerUserModeEnabled() ? 'per-user-pat' : 'jwt';
  logger.info(
    { ownerId, sourceHome, credMode },
    'bytedcli-identity: credentials prepared (git + jwt_override)',
  );

  return {
    hostDataDir: mountDataDir,
    hostGitconfig: gitconfig,
  };
}
