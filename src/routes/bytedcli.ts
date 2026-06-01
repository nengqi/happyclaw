/**
 * B 方案凭证回传端点（公开路由，nonce 鉴权，不走 authMiddleware）。
 *
 * 同事本机跑 login.sh（自己身份 bytedcli 登录 + 拿 PAT/JWT）后，脚本把凭证
 * POST 到这里。body 带 /login 签发的一次性 nonce 把回传绑到正确 user。
 *
 * POST /bytedcli/upload
 *   { nonce, pat, patId?, patExpiresAt?, bytecloudJwt?, cloudHost?, username? }
 *   → 验 nonce → 存 user_secrets.codebase_pat + bytecloud_jwt → markBytedcliAuthed
 *
 * ⚠️ 安全边界（demo 阶段，办公网 LAN + 一次性 nonce + 30min TTL）：
 *   - 明文 HTTP（同事机 → Mac mini 办公网 IP），非 HTTPS；secret 在 body 里
 *   - 合规/加固（mTLS / 端到端加密 / DB AES）"另外再说"，见 research.md
 */
import { Hono } from 'hono';

import { consumeLoginNonce } from '../bytedcli-login-nonce.js';
import {
  getUserById,
  markBytedcliAuthed,
  setUserBytecloudJwt,
  setUserCodebasePat,
} from '../db.js';
import { logger } from '../logger.js';

const bytedcliRoutes = new Hono();

bytedcliRoutes.post('/upload', async (c) => {
  const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body.nonce !== 'string') {
    return c.json({ error: 'missing nonce' }, 400);
  }

  const userId = consumeLoginNonce(body.nonce);
  if (!userId) {
    logger.warn('bytedcli-upload: invalid or expired nonce');
    return c.json({ error: 'invalid or expired nonce' }, 401);
  }

  const user = getUserById(userId);
  if (!user) {
    logger.warn({ userId }, 'bytedcli-upload: nonce maps to unknown user');
    return c.json({ error: 'unknown user' }, 404);
  }

  const pat = typeof body.pat === 'string' ? body.pat : '';
  const bytecloudJwt = typeof body.bytecloudJwt === 'string' ? body.bytecloudJwt : '';
  if (!pat && !bytecloudJwt) {
    return c.json({ error: 'no credential (need pat or bytecloudJwt)' }, 400);
  }

  if (pat) {
    setUserCodebasePat(userId, {
      token: pat,
      id: typeof body.patId === 'string' ? body.patId : '',
      expires_at: typeof body.patExpiresAt === 'string' ? body.patExpiresAt : '',
    });
  }
  if (bytecloudJwt) {
    setUserBytecloudJwt(userId, {
      token: bytecloudJwt,
      host: typeof body.cloudHost === 'string' ? body.cloudHost : '',
      saved_at: new Date().toISOString(),
    });
  }

  markBytedcliAuthed(userId);
  logger.info(
    {
      userId,
      username: typeof body.username === 'string' ? body.username : undefined,
      hasPat: !!pat,
      hasJwt: !!bytecloudJwt,
    },
    'bytedcli-upload: stored per-user credentials, marked authed',
  );

  return c.json({ ok: true });
});

export default bytedcliRoutes;
