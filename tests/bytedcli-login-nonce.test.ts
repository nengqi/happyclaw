/**
 * B 方案 login nonce 存储测试：签发 → 一次性消费 → 未知/过期返 null。
 */
import { beforeEach, describe, expect, test, vi } from 'vitest';

vi.mock('../src/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
  issueLoginNonce,
  consumeLoginNonce,
  _clearAllNonces,
} from '../src/bytedcli-login-nonce.js';

beforeEach(() => {
  _clearAllNonces();
  vi.useRealTimers();
});

describe('bytedcli login nonce', () => {
  test('签发的 nonce 能消费一次，返回绑定的 userId', () => {
    const nonce = issueLoginNonce('user-1');
    expect(typeof nonce).toBe('string');
    expect(nonce.length).toBeGreaterThan(20);
    expect(consumeLoginNonce(nonce)).toBe('user-1');
  });

  test('一次性：消费过的 nonce 再消费返 null', () => {
    const nonce = issueLoginNonce('user-2');
    expect(consumeLoginNonce(nonce)).toBe('user-2');
    expect(consumeLoginNonce(nonce)).toBeNull();
  });

  test('未知 nonce → null', () => {
    expect(consumeLoginNonce('deadbeef')).toBeNull();
  });

  test('过期 nonce → null（30min TTL）', () => {
    vi.useFakeTimers();
    const nonce = issueLoginNonce('user-3');
    vi.advanceTimersByTime(31 * 60 * 1000);
    expect(consumeLoginNonce(nonce)).toBeNull();
  });

  test('不同 user 的 nonce 互不串台', () => {
    const a = issueLoginNonce('user-a');
    const b = issueLoginNonce('user-b');
    expect(consumeLoginNonce(b)).toBe('user-b');
    expect(consumeLoginNonce(a)).toBe('user-a');
  });
});
