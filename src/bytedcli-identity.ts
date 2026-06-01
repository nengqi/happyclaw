/**
 * bytedcli 身份注入（多租户沙盒）。
 *
 * 让 member 容器内能跑 bytedcli / 拉公司代码仓库（code.byted.org）。
 * 思路抄自 rune-agent src/sandbox/bytedcli-auth-sync.ts，但适配 happyclaw
 * 的差异：
 *   - rune-agent 是长驻容器 → docker cp 把 auth 文件 upload 进运行中的容器；
 *     happyclaw 是每轮 spawn 的临时容器（docker run --rm）→ 改用 volume mount，
 *     照搬已有的 per-user feishu-cli OAuth 挂载模板（container-runner.ts）。
 *   - rune-agent 容器用户是 tiger（home /home/tiger）；happyclaw 是 node（/home/node）。
 *
 * 身份来源（demo 阶段）：宿主机操作者（部署 happyclaw 的人，如齐能）的
 * ~/.local/share/bytedcli/data。首轮 spawn 时 seed 到 per-user 目录后，该目录
 * 成为这个 member 身份的 source of truth——容器自己刷新 JWT 写回，天然实现
 * 「同一用户跨对话保留登录态」。真·多租户的 per-user 独立 SSO 抓取（rune-agent
 * bytecloud-auth.service 那套）是后续 feature，demo 不需要。
 *
 * 全部行为由 BYTEDCLI_INJECT=true 门控；未开启时本模块不被调用，容器行为不变。
 */
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  getUserBytedcliDataDir,
  hasAuthedSandbox,
} from './bytedcli-auth.js';
import { getUserById } from './db.js';
import { logger } from './logger.js';

/** 容器内 bytedcli 数据目录（node 用户）。 */
export const CONTAINER_BYTEDCLI_DATA = '/home/node/.local/share/bytedcli/data';
/** 容器内 git 全局配置路径（node 用户）。 */
export const CONTAINER_GITCONFIG = '/home/node/.gitconfig';

/** 是否开启 bytedcli 身份注入。关闭时容器完全不挂载 bytedcli 相关卷。 */
export function isBytedcliInjectEnabled(): boolean {
  return process.env.BYTEDCLI_INJECT === 'true';
}

/**
 * 是否开启 per-user SSO 模式（authed user 用自己 sandbox，pending/expired 不挂）。
 * 关 = 沿用 seed-from-operator 兜底（demo 平滑过渡）。
 */
export function isPerUserModeEnabled(): boolean {
  return process.env.BYTEDCLI_PER_USER === 'true';
}

/**
 * 从 group 推导真正应该归属的 ownerId（修 created_by bug）：
 *   member home group 的 folder 是 `home-<userId>` → 直接解析出 userId
 *   其它情况 fallback 到 group.created_by
 *
 * 背景：ensureUserHomeGroup 给 is_home=1 row 写 created_by=memberId，但 IM-bound
 * is_home=0 兄弟行是别处建的，created_by=admin。container-runner 的 spawn 用
 * is_home=0 row → 读到 admin，把 bytedcli seed 全往 admin 目录写，所有 member 共享
 * 同一份 operator 身份，per-user 隔离假性。folder 前缀解析绕开 DB 歧义。
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

/** 宿主机 bytedcli 身份数据来源目录（操作者本人的登录态）。 */
export function getBytedcliHostDataDir(): string {
  return (
    process.env.BYTEDCLI_HOST_DATA_DIR ||
    path.join(os.homedir(), '.local', 'share', 'bytedcli', 'data')
  );
}

export interface BytedcliIdentityMounts {
  /** 宿主机 per-user bytedcli data 目录 → 挂到 CONTAINER_BYTEDCLI_DATA（rw）。 */
  hostDataDir: string;
  /** 宿主机生成的 gitconfig → 挂到 CONTAINER_GITCONFIG（ro）。 */
  hostGitconfig: string;
}

/**
 * 生成容器 .gitconfig 内容：让 git 对 code.byted.org 走 bytedcli credential helper。
 * 若设置了 CODEBASE_PAT，则用 PAT 方式（比 helper 更稳，rune-agent 同款 fallback）。
 */
function buildGitconfig(): string {
  const pat = process.env.CODEBASE_PAT;
  if (pat) {
    return [
      '[credential "https://code.byted.org"]',
      `\thelper = "!f() { echo username=x-access-token; echo password=${pat}; }; f"`,
      '',
    ].join('\n');
  }
  return [
    '[credential "https://code.byted.org"]',
    '\thelper = !bytedcli auth git-credential-helper',
    '',
  ].join('\n');
}

/** seed 时跳过的条目：过期 JWT 缓存、临时 challenge 目录、大缓存/日志。 */
function shouldSkipSeedEntry(src: string): boolean {
  const base = path.basename(src);
  if (base.includes('.expired_')) return true;
  if (base === 'auth_login_challenges') return true;
  if (base === 'meego_login_challenges') return true;
  if (base === 'logs' || base === 'traces') return true;
  return false;
}

/**
 * 确保 per-user bytedcli 身份就位，返回需要挂载的宿主机路径。
 *
 * seed-once 语义：仅当 per-user data 目录不存在或为空时，从宿主机操作者的
 * bytedcli data 播种一次；此后该目录由容器自己维护（刷新 JWT）。
 * gitconfig 每次重写（幂等，无状态）。
 *
 * @param ownerId  happyclaw user id（member）
 * @param dataDir  happyclaw DATA_DIR（用于拼 config/user-cli/<ownerId>/bytedcli）
 * @returns 挂载路径，或 null（宿主无可用身份 / 未开启）
 */
export function ensureBytedcliIdentity(
  ownerId: string,
  dataDir: string,
): BytedcliIdentityMounts | null {
  if (!isBytedcliInjectEnabled()) return null;
  if (!ownerId) return null;

  const hostSource = getBytedcliHostDataDir();
  const userRoot = path.join(dataDir, 'config', 'user-cli', ownerId, 'bytedcli');
  const userDataDir = path.join(userRoot, 'data');
  const userGitconfig = path.join(userRoot, 'gitconfig');

  // gitconfig 每次重写（幂等，per-user / operator-seed 两条路径都要）
  try {
    fs.mkdirSync(userRoot, { recursive: true });
    fs.writeFileSync(userGitconfig, buildGitconfig(), { mode: 0o644 });
  } catch (err) {
    logger.warn({ ownerId, err }, 'bytedcli-identity: failed to write gitconfig');
    return null;
  }

  // Per-user 模式：按 user.bytedcli_auth_status 选数据源（authed=用户自己 sandbox / pending=不挂）
  if (isPerUserModeEnabled()) {
    const user = getUserById(ownerId);
    if (!user) {
      logger.warn({ ownerId }, 'bytedcli-identity: per-user mode but user row not found, skip mount');
      return null;
    }
    const status = user.bytedcli_auth_status;
    if (status === 'authed') {
      if (hasAuthedSandbox(ownerId, dataDir)) {
        const sandboxData = getUserBytedcliDataDir(ownerId, dataDir);
        logger.info(
          { ownerId, sandboxData },
          'bytedcli-identity: per-user authed, mounting user sandbox',
        );
        return { hostDataDir: sandboxData, hostGitconfig: userGitconfig };
      }
      logger.warn(
        { ownerId },
        'bytedcli-identity: status=authed but sandbox missing — falling back to operator seed',
      );
      // fall through to legacy seed-from-operator
    } else if (status === 'pending' || status === 'expired') {
      logger.info(
        { ownerId, status },
        'bytedcli-identity: per-user pending/expired — skipping mount, user must /login',
      );
      return null;
    }
    // status === 'none' → fall through to seed-from-operator（首次使用即赠默认身份，UX 平滑）
  }

  // Legacy / fallback：seed-from-operator（operator 真身份播种到 per-user 目录）
  // seed-once：目录已有内容则跳过播种
  let needSeed = true;
  try {
    needSeed = !fs.existsSync(userDataDir) || fs.readdirSync(userDataDir).length === 0;
  } catch {
    needSeed = true;
  }

  if (needSeed) {
    if (!fs.existsSync(hostSource)) {
      logger.warn(
        { ownerId, hostSource },
        'bytedcli-identity: host bytedcli data dir not found, skipping inject (set BYTEDCLI_HOST_DATA_DIR?)',
      );
      return null;
    }
    try {
      fs.mkdirSync(userDataDir, { recursive: true });
      // 跨 uid（宿主 vs 容器 node/1000）：用宽松读权限保证容器可读。
      // demo 阶段数据在隔离的 per-user 容器内，可接受；生产需收紧（见 research TODO）。
      fs.cpSync(hostSource, userDataDir, {
        recursive: true,
        filter: (src) => !shouldSkipSeedEntry(src),
        dereference: true,
        force: true,
      });
      relaxPermissions(userDataDir);
      logger.info(
        { ownerId, hostSource, userDataDir },
        'bytedcli-identity: seeded operator identity into per-user sandbox dir',
      );
    } catch (err) {
      logger.warn({ ownerId, err }, 'bytedcli-identity: seed failed');
      return null;
    }
  }

  return { hostDataDir: userDataDir, hostGitconfig: userGitconfig };
}

/** 递归放宽权限：目录 0o755 / 文件 0o644，让容器 node(1000) 跨 uid 可读。 */
function relaxPermissions(root: string): void {
  const walk = (p: string): void => {
    let st: fs.Stats;
    try {
      st = fs.lstatSync(p);
    } catch {
      return;
    }
    if (st.isSymbolicLink()) return;
    try {
      fs.chmodSync(p, st.isDirectory() ? 0o755 : 0o644);
    } catch {
      /* best-effort */
    }
    if (st.isDirectory()) {
      let entries: string[] = [];
      try {
        entries = fs.readdirSync(p);
      } catch {
        return;
      }
      for (const e of entries) walk(path.join(p, e));
    }
  };
  walk(root);
}
