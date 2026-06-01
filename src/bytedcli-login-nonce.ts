/**
 * B 方案登录 nonce 存储（内存，一次性，30min TTL）。
 *
 * 背景：合规禁 QR/lark OAuth 登录，per-user 身份授权改走「傻瓜脚本回传」——
 *   /login → 签发 nonce + 给同事一行 curl 命令 → 同事本机跑脚本（自己身份登录
 *   bytedcli + 拿 PAT/JWT）→ 脚本把凭证 POST 回 happyclaw /bytedcli/upload，
 *   body 带 nonce。nonce 把回传绑到正确的 user，且密钥不进对话（对话里只出现
 *   非敏感的 nonce）。
 *
 * 内存存即可：nonce 短效、一次性；happyclaw 重启则同事重发 /login。
 */
import crypto from 'crypto';

import { logger } from './logger.js';

interface NonceRecord {
  userId: string;
  expiresAt: number;
}

/** 30min：给同事足够时间装/跑脚本 + bytedcli SSO 登录。 */
const NONCE_TTL_MS = 30 * 60 * 1000;

const store = new Map<string, NonceRecord>();

/** 签发一次性 login nonce，绑定 happyclaw user id。 */
export function issueLoginNonce(userId: string): string {
  sweepExpiredNonces();
  const nonce = crypto.randomBytes(24).toString('hex');
  store.set(nonce, { userId, expiresAt: Date.now() + NONCE_TTL_MS });
  logger.info({ userId }, 'bytedcli-login: issued login nonce');
  return nonce;
}

/**
 * 消费 nonce（一次性：命中即删）。返回绑定的 userId，或 null（不存在/已过期）。
 * 即使过期也先删除（防 store 泄漏）。
 */
export function consumeLoginNonce(nonce: string): string | null {
  const rec = store.get(nonce);
  if (!rec) return null;
  store.delete(nonce);
  if (Date.now() > rec.expiresAt) {
    logger.info({ userId: rec.userId }, 'bytedcli-login: nonce expired on consume');
    return null;
  }
  return rec.userId;
}

/** 清过期 nonce（issue 时顺带调用，best-effort）。 */
export function sweepExpiredNonces(): void {
  const now = Date.now();
  for (const [k, v] of store) {
    if (now > v.expiresAt) store.delete(k);
  }
}

/** 测试用：清空。 */
export function _clearAllNonces(): void {
  store.clear();
}
