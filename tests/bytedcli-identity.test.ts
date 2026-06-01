/**
 * bytedcli-identity（回传 PAT/JWT based 身份注入）测试。
 *
 * 验证（2026-06-02 重写——B 方案：authed 用户用本机回传的 PAT/JWT，none 走 operator
 * JWT 兜底，不再有 host sandbox / ensureCodebasePat）：
 *   ① flag off → null，不写文件
 *   ② 非 per-user → operator JWT（x-jwt-token + jwt_override）
 *   ③ fetchCredentialJwts 返 null（operator 未认证）→ null
 *   ④ CODEBASE_PAT env → x-access-token:pat + best-effort operator JWT override
 *   ⑤ per-user authed + 有回传 PAT → x-access-token:PAT + 回传 JWT override，不调 fetchCredentialJwts
 *   ⑤b per-user authed 但无回传 PAT → null（强制 /login，不回落 operator）
 *   ⑥ per-user pending/expired → null
 *   ⑦ per-user none → operator JWT 兜底（不落 per-user 凭证）
 *   ⑧ getEffectiveOwnerId 修 created_by bug
 *
 * fetchCredentialJwts（execFileSync 真 bytedcli）+ db 读取 mock 掉；e2e 在 mini 验。
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

vi.mock('../src/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// db mock：getUserById（per-user status）+ 回传 PAT/JWT 读取
const mockUserState: { [id: string]: { bytedcli_auth_status: string } } = {};
const mockCodebasePat = {
  value: null as { token: string; id: string; expires_at: string } | null,
};
const mockBytecloudJwt = {
  value: null as { token: string; host: string; saved_at: string } | null,
};
vi.mock('../src/db.js', () => ({
  getUserById: (id: string) => (mockUserState[id] ? { id, ...mockUserState[id] } : undefined),
  getUserCodebasePat: () => mockCodebasePat.value,
  getUserBytecloudJwt: () => mockBytecloudJwt.value,
}));

// bytedcli-auth：fetchCredentialJwts 记录 sourceHome 调用
const fetchCalls: string[] = [];
const mockFetch = {
  value: {
    codebaseJwt: 'CB_JWT',
    bytecloudJwt: 'BC_JWT',
    cloudHost: 'https://cloud.bytedance.net',
  } as { codebaseJwt: string; bytecloudJwt: string; cloudHost: string } | null,
};
vi.mock('../src/bytedcli-auth.js', () => ({
  fetchCredentialJwts: (sourceHome: string) => {
    fetchCalls.push(sourceHome);
    return mockFetch.value;
  },
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
const gitCreds = () => path.join(dataDirPath(), '.git-credentials'); // 在 rw data 目录内
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
  mockFetch.value = {
    codebaseJwt: 'CB_JWT',
    bytecloudJwt: 'BC_JWT',
    cloudHost: 'https://cloud.bytedance.net',
  };
  mockCodebasePat.value = null;
  mockBytecloudJwt.value = null;
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

describe('ensureBytedcliIdentity — 回传 PAT/JWT based', () => {
  test('① flag off → null，不写文件', () => {
    process.env.BYTEDCLI_INJECT = 'false';
    expect(isBytedcliInjectEnabled()).toBe(false);
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
    expect(fs.existsSync(gitCreds())).toBe(false);
  });

  test('② 非 per-user → operator JWT + 生成三件套', () => {
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fetchCalls).toEqual(['/operator/home']);
    const creds = fs.readFileSync(gitCreds(), 'utf8');
    expect(creds).toContain('x-jwt-token:CB_JWT@code.byted.org');
    const gc = fs.readFileSync(gitconfig(), 'utf8');
    expect(gc).toContain('helper = store --file=');
    expect(gc).toContain('/.git-credentials');
    const ov = fs.readFileSync(
      path.join(dataDirPath(), 'jwt_override.cloud.bytedance.net.json'),
      'utf8',
    );
    expect(ov).toContain('BC_JWT');
    expect(r!.hostDataDir).toBe(dataDirPath());
    expect(r!.hostGitconfig).toBe(gitconfig());
  });

  test('② secret 文件 0600（共享机器不 world-readable）', () => {
    ensureBytedcliIdentity(OWNER, dataDir);
    expect(fs.statSync(gitCreds()).mode & 0o777).toBe(0o600);
    expect(
      fs.statSync(path.join(dataDirPath(), 'jwt_override.cloud.bytedance.net.json')).mode & 0o777,
    ).toBe(0o600);
  });

  test('③ fetchCredentialJwts 返 null（operator 未认证）→ null', () => {
    mockFetch.value = null;
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
    expect(fs.existsSync(gitCreds())).toBe(false);
  });

  test('④ CODEBASE_PAT → x-access-token:pat + best-effort operator JWT override', () => {
    process.env.CODEBASE_PAT = 'pat-xyz';
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fs.readFileSync(gitCreds(), 'utf8')).toContain('x-access-token:pat-xyz@code.byted.org');
    // env-pat 仍顺带拿 operator bytecloud JWT
    expect(fetchCalls).toEqual(['/operator/home']);
    expect(fs.existsSync(path.join(dataDirPath(), 'jwt_override.cloud.bytedance.net.json'))).toBe(
      true,
    );
  });

  test('⑤ per-user authed + 回传 PAT/JWT → 用用户自己的凭证，不调 fetchCredentialJwts', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'authed' };
    mockCodebasePat.value = { token: 'USER_PAT', id: 'pid', expires_at: '2099-01-01' };
    mockBytecloudJwt.value = {
      token: 'USER_BC_JWT',
      host: 'https://cloud.tiktok-row.net',
      saved_at: '2026-06-02',
    };
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fs.readFileSync(gitCreds(), 'utf8')).toContain('x-access-token:USER_PAT@code.byted.org');
    // authed 走 DB 凭证，不调 operator fetchCredentialJwts
    expect(fetchCalls).toEqual([]);
    // 回传 JWT 写到对应 host 的 override
    const ov = fs.readFileSync(
      path.join(dataDirPath(), 'jwt_override.cloud.tiktok-row.net.json'),
      'utf8',
    );
    expect(ov).toContain('USER_BC_JWT');
  });

  test('⑤b per-user authed 但无回传 PAT → null（强制 /login，不回落 operator）', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'authed' };
    mockCodebasePat.value = null;
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
    expect(fetchCalls).toEqual([]); // 不回落 operator
    expect(fs.existsSync(gitCreds())).toBe(false);
  });

  test('⑥ per-user pending → null', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'pending' };
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
  });

  test('⑥b per-user expired → null', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'expired' };
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
  });

  test('⑦ per-user none → operator JWT 兜底（x-jwt-token，不落 per-user 凭证）', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    mockUserState[OWNER] = { bytedcli_auth_status: 'none' };
    const r = ensureBytedcliIdentity(OWNER, dataDir);
    expect(r).not.toBeNull();
    expect(fetchCalls).toEqual(['/operator/home']);
    expect(fs.readFileSync(gitCreds(), 'utf8')).toContain('x-jwt-token:CB_JWT@code.byted.org');
  });

  test('per-user user row 缺失 → null', () => {
    process.env.BYTEDCLI_PER_USER = 'true';
    // mockUserState 不设 OWNER → getUserById undefined
    expect(ensureBytedcliIdentity(OWNER, dataDir)).toBeNull();
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
