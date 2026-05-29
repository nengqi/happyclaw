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

import {
  ensureBytedcliIdentity,
  isBytedcliInjectEnabled,
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
