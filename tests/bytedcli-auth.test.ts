/**
 * bytedcli per-user SSO 流的纯函数 helper 测试（subprocess 包装函数依赖真 bytedcli binary，
 * 不在单测覆盖，e2e 在 mac mini 上跑 /login 验证）。
 *
 * 覆盖：getUserBytedcliSandbox / getUserBytedcliDataDir 路径推导、hasAuthedSandbox bytecloud-auth 探测。
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

vi.mock('../src/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
  getUserBytedcliSandbox,
  getUserBytedcliDataDir,
  hasAuthedSandbox,
} from '../src/bytedcli-auth.js';

let tmp: string;
const OWNER = 'user-xyz';

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'bytedcli-auth-test-'));
});

afterEach(() => {
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

describe('bytedcli-auth path helpers', () => {
  test('getUserBytedcliSandbox 拼成 <dataDir>/config/user-cli/<userId>/bytedcli-sandbox', () => {
    const p = getUserBytedcliSandbox(OWNER, tmp);
    expect(p).toBe(path.join(tmp, 'config', 'user-cli', OWNER, 'bytedcli-sandbox'));
  });

  test('getUserBytedcliDataDir 嵌套到 sandbox/.local/share/bytedcli/data（bytedcli HOME-rooted 实测路径）', () => {
    const p = getUserBytedcliDataDir(OWNER, tmp);
    expect(p).toBe(
      path.join(
        tmp,
        'config',
        'user-cli',
        OWNER,
        'bytedcli-sandbox',
        '.local',
        'share',
        'bytedcli',
        'data',
      ),
    );
  });

  test('hasAuthedSandbox 不存在 / 空目录 / 缺 bytecloud-auth 都返 false', () => {
    expect(hasAuthedSandbox(OWNER, tmp)).toBe(false);
    fs.mkdirSync(getUserBytedcliDataDir(OWNER, tmp), { recursive: true });
    expect(hasAuthedSandbox(OWNER, tmp)).toBe(false);
    fs.writeFileSync(path.join(getUserBytedcliDataDir(OWNER, tmp), 'sso_session.json'), '{}');
    expect(hasAuthedSandbox(OWNER, tmp)).toBe(false);
  });

  test('hasAuthedSandbox 见 bytecloud-auth/ 返 true（authed 关键标志）', () => {
    fs.mkdirSync(path.join(getUserBytedcliDataDir(OWNER, tmp), 'bytecloud-auth'), {
      recursive: true,
    });
    expect(hasAuthedSandbox(OWNER, tmp)).toBe(true);
  });
});
