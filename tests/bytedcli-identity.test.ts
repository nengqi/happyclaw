/**
 * bytedcli 身份注入（多租户沙盒）测试。
 *
 * 验证核心行为：
 *   ① BYTEDCLI_INJECT 未开 → ensureBytedcliIdentity 返回 null，不 seed 不写 gitconfig
 *   ② 开启 + 宿主有身份 → seed data 目录 + 写 gitconfig + 返回挂载路径
 *   ③ seed-once 幂等：第二次调用不覆盖容器已改的文件
 *   ④ 宿主源缺失 → 返回 null（不挂载）
 *   ⑤ .expired_ JWT 缓存 / challenge 目录不被 seed 进去
 *   ⑥ gitconfig 默认走 credential helper；设了 CODEBASE_PAT 走 PAT 形式
 *
 * 仅依赖 ./logger.js，mock 掉即可完全隔离（不碰 config.js / DB）。
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

vi.mock('../src/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// Mock db.ts 整体（避免 import 时初始化 better-sqlite3）。仅暴露 ensureBytedcliIdentity 用到的
// getUserById；per-user 分支测试直接控制 user.bytedcli_auth_status。
const mockUserState: { [id: string]: { bytedcli_auth_status: string } } = {};
vi.mock('../src/db.js', () => ({
  getUserById: (id: string) => (mockUserState[id] ? { id, ...mockUserState[id] } : undefined),
}));

import {
  ensureBytedcliIdentity,
  isBytedcliInjectEnabled,
  isPerUserModeEnabled,
  getEffectiveOwnerId,
} from '../src/bytedcli-identity.js';

let tmp: string;
let hostData: string;
let dataDir: string;
const OWNER = 'user-abc';
const savedEnv = { ...process.env };

function seedHost(): void {
  // 模拟宿主机 ~/.local/share/bytedcli/data 的关键内容
  fs.mkdirSync(path.join(hostData, 'bytecloud-auth', 'auth'), { recursive: true });
  fs.writeFileSync(path.join(hostData, 'sso_session.json'), '{"sso":"x"}');
  fs.writeFileSync(path.join(hostData, 'jwt.cloud.tiktok-row.net.json'), '{"jwt":"live"}');
  fs.writeFileSync(path.join(hostData, 'jwt.cloud.tiktok-row.net.json.expired_113547'), 'stale');
  fs.writeFileSync(path.join(hostData, 'bytecloud-auth', 'auth', 'cred'), 'secret');
  fs.mkdirSync(path.join(hostData, 'auth_login_challenges'), { recursive: true });
  fs.writeFileSync(path.join(hostData, 'auth_login_challenges', 'tmp'), 'challenge');
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bytedcli-id-test-'));
  hostData = path.join(tmp, 'host-data');
  dataDir = path.join(tmp, 'happyclaw-data');
  fs.mkdirSync(dataDir, { recursive: true });
  process.env.BYTEDCLI_HOST_DATA_DIR = hostData;
  delete process.env.CODEBASE_PAT;
  process.env.BYTEDCLI_INJECT = 'true';
});

afterEach(() => {
  process.env = { ...savedEnv };
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

const userDataDir = () =>
  path.join(dataDir, 'config', 'user-cli', OWNER, 'bytedcli', 'data');
const userGitconfig = () =>
  path.join(dataDir, 'config', 'user-cli', OWNER, 'bytedcli', 'gitconfig');

describe('bytedcli-identity', () => {
  test('① flag 未开 → 返回 null，不产生任何文件', () => {
    process.env.BYTEDCLI_INJECT = 'false';
    expect(isBytedcliInjectEnabled()).toBe(false);
    seedHost();
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).toBeNull();
    expect(fs.existsSync(userGitconfig())).toBe(false);
    expect(fs.existsSync(userDataDir())).toBe(false);
  });

  test('② 开启 + 宿主有身份 → seed data + 写 gitconfig + 返回挂载路径', () => {
    seedHost();
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(r!.hostDataDir).toBe(userDataDir());
    expect(r!.hostGitconfig).toBe(userGitconfig());
    // 关键文件被 seed 进去
    expect(fs.readFileSync(path.join(userDataDir(), 'sso_session.json'), 'utf8')).toContain('sso');
    expect(fs.existsSync(path.join(userDataDir(), 'bytecloud-auth', 'auth', 'cred'))).toBe(true);
    // gitconfig 默认 credential helper
    const gc = fs.readFileSync(userGitconfig(), 'utf8');
    expect(gc).toContain('https://code.byted.org');
    expect(gc).toContain('bytedcli auth git-credential-helper');
  });

  test('⑤ .expired_ 与 challenge 目录不被 seed', () => {
    seedHost();
    ensureBytedcliIdentity(OWNER, dataDir);
    const files = fs.readdirSync(userDataDir());
    expect(files.some((f) => f.includes('.expired_'))).toBe(false);
    expect(files).not.toContain('auth_login_challenges');
    expect(files).toContain('jwt.cloud.tiktok-row.net.json');
  });

  test('③ seed-once 幂等：第二次调用不覆盖容器已改的文件', () => {
    seedHost();
    ensureBytedcliIdentity(OWNER, dataDir);
    // 模拟容器刷新了 JWT
    const jwt = path.join(userDataDir(), 'jwt.cloud.tiktok-row.net.json');
    fs.writeFileSync(jwt, '{"jwt":"refreshed-by-container"}');
    // 再次调用（下一轮 spawn）
    const r2 = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r2).not.toBeNull();
    expect(fs.readFileSync(jwt, 'utf8')).toContain('refreshed-by-container');
  });

  test('④ 宿主源缺失 → 返回 null（首次 seed 无源）', () => {
    // 不调 seedHost()，hostData 不存在
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).toBeNull();
    expect(fs.existsSync(userDataDir())).toBe(false);
  });

  test('⑥ CODEBASE_PAT 设置 → gitconfig 走 PAT 形式', () => {
    process.env.CODEBASE_PAT = 'pat-token-xyz';
    seedHost();
    ensureBytedcliIdentity(OWNER, dataDir);
    const gc = fs.readFileSync(userGitconfig(), 'utf8');
    expect(gc).toContain('x-access-token');
    expect(gc).toContain('pat-token-xyz');
    expect(gc).not.toContain('bytedcli auth git-credential-helper');
  });
});

describe('getEffectiveOwnerId — 修 created_by 错位 bug', () => {
  test('member home folder `home-<userId>` 解析出 userId（绕开 IM-bound 行 created_by=admin）', () => {
    expect(
      getEffectiveOwnerId({ folder: 'home-0f8e893e-abc', created_by: 'admin-xxx' }),
    ).toBe('0f8e893e-abc');
  });
  test('非 home- 前缀（如 admin folder=main）回落到 group.created_by', () => {
    expect(getEffectiveOwnerId({ folder: 'main', created_by: 'admin-1' })).toBe('admin-1');
  });
  test('home- 前缀但 userId 部分为空 → 回落 created_by', () => {
    expect(getEffectiveOwnerId({ folder: 'home-', created_by: 'cb' })).toBe('cb');
  });
});

describe('ensureBytedcliIdentity — per-user 模式分支', () => {
  beforeEach(() => {
    process.env.BYTEDCLI_PER_USER = 'true';
    for (const k of Object.keys(mockUserState)) delete mockUserState[k];
  });

  test('flag on + user.status=authed + sandbox 实存 → mount 用户自己 sandbox（非 operator seed）', () => {
    mockUserState[OWNER] = { bytedcli_auth_status: 'authed' };
    // 模拟用户自己的 sandbox 完成 SSO 后产生的 bytecloud-auth/ 真实目录
    const sandboxData = path.join(
      dataDir,
      'config',
      'user-cli',
      OWNER,
      'bytedcli-sandbox',
      '.local',
      'share',
      'bytedcli',
      'data',
    );
    fs.mkdirSync(path.join(sandboxData, 'bytecloud-auth'), { recursive: true });
    seedHost(); // 故意也放 operator data，证明 authed 不取这个
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(r!.hostDataDir).toBe(sandboxData);
  });

  test('flag on + status=pending → null（不挂载，强制 /login）', () => {
    mockUserState[OWNER] = { bytedcli_auth_status: 'pending' };
    seedHost();
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).toBeNull();
    // operator-seed 目录不该产生
    expect(fs.existsSync(userDataDir())).toBe(false);
  });

  test('flag on + status=expired → null（同 pending）', () => {
    mockUserState[OWNER] = { bytedcli_auth_status: 'expired' };
    seedHost();
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
  });

  test('flag on + status=none → 落 operator seed 兜底（UX 平滑过渡）', () => {
    mockUserState[OWNER] = { bytedcli_auth_status: 'none' };
    seedHost();
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(r!.hostDataDir).toBe(userDataDir());
  });

  test('flag on + status=authed 但 sandbox 缺失（authed 历史残留）→ 回落 operator seed', () => {
    mockUserState[OWNER] = { bytedcli_auth_status: 'authed' };
    // 不建 bytecloud-auth/
    seedHost();
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(r!.hostDataDir).toBe(userDataDir());
  });

  test('flag off → 完全不走 per-user 分支，行为同旧版（authed 也走 operator seed）', () => {
    delete process.env.BYTEDCLI_PER_USER;
    expect(isPerUserModeEnabled()).toBe(false);
    mockUserState[OWNER] = { bytedcli_auth_status: 'authed' };
    seedHost();
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(r!.hostDataDir).toBe(userDataDir());
  });

  test('flag on + 用户不存在 DB → null（防御性，没用户不挂）', () => {
    // 不写 mockUserState[OWNER]
    seedHost();
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
  });
});
