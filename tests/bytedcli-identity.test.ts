/**
 * bytedcli-identity（JWT-based 身份注入）测试。
 *
 * 验证（2026-06-01 重写——裸 mount device key 死路后改 JWT 注入）：
 *   ① flag off → null，不写文件
 *   ② inject on 非 per-user → operator HOME 拿 JWT，生成 .git-credentials(含 codebase jwt)
 *      + .gitconfig(helper=store) + jwt_override(含 bytecloud jwt)
 *   ③ fetchCredentialJwts 返 null（源未认证）→ ensureBytedcliIdentity null
 *   ④ CODEBASE_PAT → .git-credentials 用 x-access-token:pat，不调 fetchCredentialJwts
 *   ⑤ per-user authed + sandbox 存在 → sourceHome = sandbox（非 operator）
 *   ⑥ per-user pending/expired → null（强制 /login）
 *   ⑦ per-user none → operator 兜底
 *   ⑧ getEffectiveOwnerId 修 created_by bug
 *
 * fetchCredentialJwts（execFileSync 真 bytedcli）+ db.getUserById mock 掉；e2e 在 mini 验。
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

vi.mock('../src/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// db.getUserById：per-user 分支控制 user.bytedcli_auth_status
const mockUserState: { [id: string]: { bytedcli_auth_status: string } } = {};
vi.mock('../src/db.js', () => ({
  getUserById: (id: string) => (mockUserState[id] ? { id, ...mockUserState[id] } : undefined),
}));

// bytedcli-auth：fetchCredentialJwts 返固定 JWT（记录被调的 sourceHome）；sandbox 路径 helper
const fetchCalls: string[] = [];
const mockFetch = { value: { codebaseJwt: 'CB_JWT', bytecloudJwt: 'BC_JWT', cloudHost: 'https://cloud.bytedance.net' } as { codebaseJwt: string; bytecloudJwt: string; cloudHost: string } | null };
const mockHasAuthed = { value: true };
vi.mock('../src/bytedcli-auth.js', () => ({
  fetchCredentialJwts: (sourceHome: string) => {
    fetchCalls.push(sourceHome);
    return mockFetch.value;
  },
  getUserBytedcliSandbox: (uid: string, dd: string) =>
    path.join(dd, 'config', 'user-cli', uid, 'bytedcli-sandbox'),
  hasAuthedSandbox: () => mockHasAuthed.value,
}));

import {
  ensureBytedcliIdentity,
  isBytedcliInjectEnabled,
  isPerUserModeEnabled,
  getEffectiveOwnerId,
} from '../src/bytedcli-identity.js';

let tmp: string;
let dataDir: string;
const OWNER = 'user-abc';
const savedEnv = { ...process.env };

const mountRoot = () => path.join(dataDir, 'config', 'user-cli', OWNER, 'bytedcli-mount');
const dataDirPath = () => path.join(mountRoot(), 'data');
const gitCreds = () => path.join(dataDirPath(), '.git-credentials'); // 移到 rw data 目录内
const gitconfig = () => path.join(mountRoot(), '.gitconfig');

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bytedcli-id-test-'));
  dataDir = path.join(tmp, 'happyclaw-data');
  fs.mkdirSync(dataDir, { recursive: true });
  process.env.BYTEDCLI_INJECT = 'true';
  delete process.env.BYTEDCLI_PER_USER;
  delete process.env.CODEBASE_PAT;
  process.env.BYTEDCLI_SOURCE_HOME = '/operator/home';
  fetchCalls.length = 0;
  mockFetch.value = { codebaseJwt: 'CB_JWT', bytecloudJwt: 'BC_JWT', cloudHost: 'https://cloud.bytedance.net' };
  mockHasAuthed.value = true;
  for (const k of Object.keys(mockUserState)) delete mockUserState[k];
});

afterEach(() => {
  process.env = { ...savedEnv };
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('ensureBytedcliIdentity — JWT-based', () => {
  test('① flag off → null，不写文件', () => {
    process.env.BYTEDCLI_INJECT = 'false';
    expect(isBytedcliInjectEnabled()).toBe(false);
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
    expect(fs.existsSync(gitCreds())).toBe(false);
  });

  test('② inject on 非 per-user → operator HOME + 生成三件套', () => {
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    // sourceHome 用 operator
    expect(fetchCalls).toEqual(['/operator/home']);
    // .git-credentials 含 codebase jwt
    const creds = fs.readFileSync(gitCreds(), 'utf8');
    expect(creds).toContain('x-jwt-token:CB_JWT@code.byted.org');
    // .gitconfig helper=store --file 指向 rw data 目录（避免 ro 写回 warning）
    const gc = fs.readFileSync(gitconfig(), 'utf8');
    expect(gc).toContain('helper = store --file=');
    expect(gc).toContain('/.git-credentials');
    // jwt_override 含 bytecloud jwt
    const ov = fs.readFileSync(
      path.join(dataDirPath(), 'jwt_override.cloud.bytedance.net.json'),
      'utf8',
    );
    expect(ov).toContain('BC_JWT');
    expect(ov).toContain('https://cloud.bytedance.net');
    // 返回路径正确（.git-credentials 在 data 目录内，随 data mount 进容器）
    expect(fs.existsSync(gitCreds())).toBe(true);
    expect(r!.hostDataDir).toBe(dataDirPath());
    expect(r!.hostGitconfig).toBe(gitconfig());
  });

  test('③ fetchCredentialJwts 返 null（源未认证）→ null', () => {
    mockFetch.value = null;
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
    expect(fs.existsSync(gitCreds())).toBe(false);
  });

  test('④ CODEBASE_PAT → .git-credentials 用 pat，不调 fetchCredentialJwts', () => {
    process.env.CODEBASE_PAT = 'pat-xyz';
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fetchCalls).toEqual([]); // pat 模式不拿 jwt
    expect(fs.readFileSync(gitCreds(), 'utf8')).toContain('x-access-token:pat-xyz@code.byted.org');
  });

  test('⑤ per-user authed + sandbox 存在 → sourceHome = sandbox', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'authed' };
    mockHasAuthed.value = true;
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fetchCalls[0]).toBe(
      path.join(dataDir, 'config', 'user-cli', OWNER, 'bytedcli-sandbox'),
    );
  });

  test('⑥ per-user pending → null（强制 /login）', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'pending' };
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
    expect(fetchCalls).toEqual([]);
  });

  test('⑥b per-user expired → null', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'expired' };
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
  });

  test('⑦ per-user none → operator 兜底', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'none' };
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fetchCalls).toEqual(['/operator/home']);
  });

  test('per-user authed 但 sandbox 缺失 → 回落 operator', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'authed' };
    mockHasAuthed.value = false;
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fetchCalls).toEqual(['/operator/home']);
  });
});

describe('getEffectiveOwnerId — 修 created_by 错位 bug', () => {
  test('home-<userId> 解析 userId（绕开 created_by=admin）', () => {
    expect(getEffectiveOwnerId({ folder: 'home-0f8e893e', created_by: 'admin' })).toBe('0f8e893e');
  });
  test('非 home- 前缀 → created_by', () => {
    expect(getEffectiveOwnerId({ folder: 'main', created_by: 'admin-1' })).toBe('admin-1');
  });
  test('home- 空 userId → created_by', () => {
    expect(getEffectiveOwnerId({ folder: 'home-', created_by: 'cb' })).toBe('cb');
  });
});

describe('flag helpers', () => {
  test('isPerUserModeEnabled', () => {
    delete process.env.BYTEDCLI_PER_USER;
    expect(isPerUserModeEnabled()).toBe(false);
    process.env.BYTEDCLI_PER_USER = 'true';
    expect(isPerUserModeEnabled()).toBe(true);
  });
});
