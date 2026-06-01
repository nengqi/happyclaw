/**
 * bytedcli 身份注入（多租户沙盒）——回传 PAT/JWT based（B 方案）。
 *
 * 让容器内能用真人身份跑 bytedcli / git 拉 code.byted.org。
 *
 * ★ 关键约束（2026-06-01 实测）：bytedcli 凭证文件用机器级 device key（macOS
 *   keychain）加密，**裸 mount 凭证文件进 linux 容器解不开**（authenticated:False）。
 *   唯一活路 = 注入自包含凭证（PAT / JWT，不依赖 device key）。
 *
 * 身份来源（per-user 模式）：
 *   - authed：同事本机跑 login.sh 自己身份登录 → 拿 codebase PAT + bytecloud JWT
 *     → POST 回 /bytedcli/upload 存 DB（user_secrets.codebase_pat / bytecloud_jwt）。
 *     这里直接读 DB 写凭证文件 → 真 per-user 身份。
 *   - none：operator 兜底（首次体验赠默认身份）——走 operator HOME 的短效 codebase
 *     JWT，**不落任何 per-user 凭证**（避免 operator 凭证污染用户记录）。
 *   - pending/expired：null（不挂，强制 /login）。
 *   非 per-user / CODEBASE_PAT env：operator 单身份。
 *
 * 文件：
 *   - .git-credentials（`https://x-access-token:<pat>@...` 或 `x-jwt-token:<jwt>`）
 *     + .gitconfig（helper=store --file）→ git 拉代码
 *   - data/jwt_override.cloud.<host>.json（bytecloud JWT）→ 容器内 bytedcli 命令
 *
 * 全部行为由 BYTEDCLI_INJECT=true 门控；未开启时不挂载，容器行为不变。
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

import { fetchCredentialJwts } from './bytedcli-auth.js';
import {
  getUserById,
  getUserCodebasePat,
  getUserBytecloudJwt,
  type BytecloudJwtRecord,
  type CodebasePatRecord,
} from './db.js';
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
 * 是否开启 per-user 身份模式（authed user 用自己回传的凭证，none 用 operator 兜底，
 * pending/expired 不挂）。关 = operator 单身份（demo / fallback）。
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
 * operator 凭证来源 HOME（非 per-user 模式 / per-user status=none 兜底时用）。
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

type PerUserCredential =
  | { mode: 'skip' }
  | { mode: 'operator' }
  | { mode: 'authed'; pat: CodebasePatRecord; jwt: BytecloudJwtRecord | null };

/**
 * per-user 模式下决定该 owner 用什么凭证：
 *   authed + 有回传 PAT → 用户自己的凭证；authed 但无回传 PAT → skip（强制 /login，
 *     不静默回落 operator 破坏隔离）；pending/expired → skip；none → operator 兜底。
 */
function resolvePerUserCredential(ownerId: string): PerUserCredential {
  const user = getUserById(ownerId);
  if (!user) {
    logger.warn({ ownerId }, 'bytedcli-identity: per-user mode but user row not found, skip');
    return { mode: 'skip' };
  }
  const status = user.bytedcli_auth_status;
  if (status === 'authed') {
    const pat = getUserCodebasePat(ownerId);
    if (!pat?.token) {
      logger.warn(
        { ownerId },
        'bytedcli-identity: status=authed but no uploaded PAT — force /login (no operator fallback)',
      );
      return { mode: 'skip' };
    }
    return { mode: 'authed', pat, jwt: getUserBytecloudJwt(ownerId) };
  }
  if (status === 'pending' || status === 'expired') {
    logger.info(
      { ownerId, status },
      'bytedcli-identity: per-user pending/expired — skip mount, user must /login',
    );
    return { mode: 'skip' };
  }
  // none → operator 兜底
  return { mode: 'operator' };
}

/**
 * 确保容器 bytedcli 身份就位，返回挂载路径。每轮 spawn 调一次。
 *
 * 凭证优先级：① CODEBASE_PAT env（operator 显式 PAT）② per-user 回传凭证（authed）/
 *            operator 兜底（none）③ 非 per-user operator JWT 单身份。
 *
 * @param ownerId  happyclaw user id（经 getEffectiveOwnerId 解析）
 * @param dataDir  happyclaw DATA_DIR
 * @returns 挂载路径，或 null（未开启 / 源未认证 / per-user skip）
 */
export function ensureBytedcliIdentity(
  ownerId: string,
  dataDir: string,
): BytedcliIdentityMounts | null {
  if (!isBytedcliInjectEnabled()) return null;
  if (!ownerId) return null;

  let credLine: string;
  let bytecloudJwt = '';
  let cloudHost = 'https://cloud.bytedance.net';
  let credMode: string;

  const envPat = process.env.CODEBASE_PAT;
  if (envPat) {
    // operator 显式 PAT（demo / 单身份）；顺带 operator bytecloud JWT（best-effort）
    credLine = gitCredLine('x-access-token', envPat);
    const jwts = fetchCredentialJwts(getOperatorSourceHome());
    if (jwts) {
      bytecloudJwt = jwts.bytecloudJwt;
      cloudHost = jwts.cloudHost;
    }
    credMode = 'env-pat';
  } else if (isPerUserModeEnabled()) {
    const cred = resolvePerUserCredential(ownerId);
    if (cred.mode === 'skip') return null;
    if (cred.mode === 'authed') {
      // 用户自己回传的凭证（真 per-user 身份）
      credLine = gitCredLine('x-access-token', cred.pat.token);
      if (cred.jwt) {
        bytecloudJwt = cred.jwt.token;
        cloudHost = cred.jwt.host || cloudHost;
      }
      credMode = 'per-user-pat';
    } else {
      // operator 兜底（status=none）：operator JWT 路径，不落任何 per-user 凭证（rv #1 防污染）
      const jwts = fetchCredentialJwts(getOperatorSourceHome());
      if (!jwts) {
        logger.warn(
          { ownerId },
          'bytedcli-identity: operator fallback but operator not authed, skip',
        );
        return null;
      }
      credLine = gitCredLine('x-jwt-token', jwts.codebaseJwt);
      bytecloudJwt = jwts.bytecloudJwt;
      cloudHost = jwts.cloudHost;
      credMode = 'operator-jwt';
    }
  } else {
    // 非 per-user：operator JWT 单身份
    const jwts = fetchCredentialJwts(getOperatorSourceHome());
    if (!jwts) {
      logger.warn(
        { ownerId },
        'bytedcli-identity: fetchCredentialJwts failed (operator not authed), skip mount',
      );
      return null;
    }
    credLine = gitCredLine('x-jwt-token', jwts.codebaseJwt);
    bytecloudJwt = jwts.bytecloudJwt;
    cloudHost = jwts.cloudHost;
    credMode = 'operator-jwt';
  }

  const mountRoot = path.join(dataDir, 'config', 'user-cli', ownerId, 'bytedcli-mount');
  const mountDataDir = path.join(mountRoot, 'data');
  // .git-credentials 放 rw 的 data 目录内（gitconfig helper --file 指向它），git store 可写回。
  const gitCredentials = path.join(mountDataDir, '.git-credentials');
  const gitconfig = path.join(mountRoot, '.gitconfig');

  try {
    fs.mkdirSync(mountDataDir, { recursive: true });
    // git 凭证（PAT 长效复用 / JWT 每轮 fresh）——含明文 secret，0600 + chmod 兜旧文件权限
    // （writeFileSync 的 mode 对已存在文件不一定改旧权限；共享机器上别 world-readable）。
    fs.writeFileSync(gitCredentials, credLine, { mode: 0o600 });
    fs.chmodSync(gitCredentials, 0o600);
    fs.writeFileSync(gitconfig, buildGitconfig(), { mode: 0o644 });
    // 清上一轮残留 jwt_override（mountDataDir 跨 spawn 稳定；旧 host/旧身份 override 不清
    // 会被容器继续用 → 身份串台 / stale JWT）。.git-credentials 不匹配此 glob，安全。
    for (const f of fs.readdirSync(mountDataDir)) {
      if (f.startsWith('jwt_override.') && f.endsWith('.json')) {
        try {
          fs.unlinkSync(path.join(mountDataDir, f));
        } catch {
          /* ignore */
        }
      }
    }
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
        { mode: 0o600 },
      );
      fs.chmodSync(overrideFile, 0o600);
    }
  } catch (err) {
    logger.warn({ ownerId, err }, 'bytedcli-identity: failed to write credential files');
    return null;
  }

  logger.info(
    { ownerId, credMode },
    'bytedcli-identity: credentials prepared (git + jwt_override)',
  );

  return {
    hostDataDir: mountDataDir,
    hostGitconfig: gitconfig,
  };
}
