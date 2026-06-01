/**
 * bytedcli per-user SSO 流（多租户 cookie 注入第二阶段）。
 *
 * 实测：bytedcli 用 `process.env.HOME` 决定 auth 数据根，
 * 设 `HOME=<sandbox>` 可让 bytedcli 完全隔离每个 happyclaw user 的临时认证空间。
 *   - 默认 HOME：bytedcli auth status 看到 operator 真实认证
 *   - HOME=/tmp/x：bytedcli auth status 报 authenticated=false，写到 /tmp/x/.local/share/bytedcli/，真目录 0 触碰
 *
 * 非阻塞 begin/complete 流（`--feishu` 只支持 blocking，非 bot 友好）：
 *   1. begin：返回 complete_token + qr_image_path（180×180 PNG 2.2KB）+ qr_url
 *   2. 用户用 Feishu app 或任意 SSO 客户端扫码完成 bytedance SSO
 *   3. poll complete：返回 login_status pending|complete|expired
 *   4. complete 后 sandbox 下生成 bytecloud-auth/ + sso_session.json + jwt.*.json
 *   5. happyclaw 把 sandbox/.local/share/bytedcli/data 当作 container mount 源
 *
 * 全部 host-side 调用；container 内不跑 bytedcli auth login。
 */
import { execFile } from 'child_process';
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';

import { logger } from './logger.js';

const execFileAsync = promisify(execFile);

/** Per-user sandbox HOME root，bytedcli 数据隔离锚点。 */
export function getUserBytedcliSandbox(userId: string, dataDir: string): string {
  return path.join(dataDir, 'config', 'user-cli', userId, 'bytedcli-sandbox');
}

/** bytedcli 在 sandbox HOME 下实际写 auth 数据的路径（与 ~/.local/share/bytedcli/data 同结构）。 */
export function getUserBytedcliDataDir(userId: string, dataDir: string): string {
  return path.join(
    getUserBytedcliSandbox(userId, dataDir),
    '.local',
    'share',
    'bytedcli',
    'data',
  );
}

/** bytedcli binary 路径，可由 env 覆盖（mini 上跟 happyclaw 实际安装路径走）。 */
function bytedcliBin(): string {
  return process.env.BYTEDCLI_BIN || 'bytedcli';
}

/** bytedcli `--site`（cn / boe / i18n / ...），default cn。 */
function bytedcliSite(): string {
  return process.env.BYTEDCLI_SITE || 'cn';
}

/** 跑 bytedcli 一条命令在指定 user 的 sandbox HOME 下，返回 stdout/stderr 给上层 parse。 */
async function runUnderSandbox(
  userId: string,
  dataDir: string,
  args: string[],
  timeoutMs = 30_000,
): Promise<{ stdout: string; stderr: string }> {
  const sandbox = getUserBytedcliSandbox(userId, dataDir);
  fs.mkdirSync(sandbox, { recursive: true });
  // bytedcli 自身会建 .local/share/bytedcli/{data,traces,cache} 子树，无需预创建。

  // 透传父进程 env，仅覆盖 HOME（决定 bytedcli 数据根）。PATH/LANG/TZ/CorpLink 相关 env 必须保留，
  // 否则 bytedcli 既找不到 git/openssl 等依赖，也连不上字节内网 SSO。
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: sandbox };

  try {
    return await execFileAsync(bytedcliBin(), args, {
      env,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
    });
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string };
    // bytedcli 在 challenge 期间 exit code 非 0 但 stdout 有 JSON 是常态（pending 也走 stderr 路径）
    if (e.stdout || e.stderr) {
      return { stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
    }
    throw err;
  }
}

/**
 * 从 bytedcli 多行 stdout 提取最后一个完整 JSON 对象。
 * bytedcli --json 会先输出若干 event 行（如 `{"event":"qr_image_ready",...}`）再输出最终 result 行。
 * 最终行是 `{"status":"success"|"error",...}`，取它。
 */
function extractFinalJson(stdout: string): Record<string, unknown> | null {
  const lines = stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      // 只接受结果型 JSON（含 status 字段），跳过事件型（如 qr_image_ready）。
      if (typeof parsed.status === 'string') return parsed;
    } catch {
      /* ignore */
    }
  }
  return null;
}

export interface BeginAuthResult {
  completeToken: string;
  qrImagePath: string;
  qrUrl: string;
}

/**
 * 发起 SSO challenge：写 sandbox 下 qr.png + 返回 complete_token / qr_url。
 * 不真扫码，调用立即返回（实测延迟 ~75ms）。
 */
export async function beginAuth(
  userId: string,
  dataDir: string,
): Promise<BeginAuthResult> {
  const sandbox = getUserBytedcliSandbox(userId, dataDir);
  const qrPath = path.join(sandbox, 'qr.png');

  const { stdout } = await runUnderSandbox(
    userId,
    dataDir,
    [
      '--site',
      bytedcliSite(),
      'auth',
      'login',
      '--session',
      '--begin',
      '--qr-image',
      qrPath,
      '--json',
    ],
    20_000,
  );

  const result = extractFinalJson(stdout);
  if (!result || result.status !== 'success') {
    const errMsg = (result?.error as { message?: string })?.message ?? 'unknown';
    throw new Error(`bytedcli begin failed: ${errMsg}`);
  }

  const data = result.data as {
    complete_token?: string;
    qr_image_path?: string;
    qr_url?: string;
  };
  if (!data?.complete_token || !data?.qr_image_path) {
    throw new Error('bytedcli begin returned no token/qr');
  }

  logger.info(
    { userId, completeToken: data.complete_token, qrImagePath: data.qr_image_path },
    'bytedcli-auth: SSO challenge created',
  );

  return {
    completeToken: data.complete_token,
    qrImagePath: data.qr_image_path,
    qrUrl: data.qr_url ?? '',
  };
}

export type PollLoginStatus = 'pending' | 'complete' | 'expired';

export interface PollCompleteResult {
  loginStatus: PollLoginStatus;
  /** bytedcli 在 sandbox 下写 auth 完整数据的路径（loginStatus='complete' 时填）。 */
  authedDataDir?: string;
}

/**
 * 轮询单次 complete 请求：返回当前 login_status。
 * happyclaw 后台调度 setInterval(5s, max 5min) 调本函数，commit/expire 自行更新 DB。
 */
export async function pollComplete(
  userId: string,
  dataDir: string,
  completeToken: string,
): Promise<PollCompleteResult> {
  const { stdout } = await runUnderSandbox(
    userId,
    dataDir,
    [
      '--site',
      bytedcliSite(),
      'auth',
      'login',
      '--complete',
      completeToken,
      '--json',
    ],
    15_000,
  );

  const result = extractFinalJson(stdout);
  if (!result) {
    // 把无法 parse 的输出当作 expired，避免无限轮询
    logger.warn({ userId, stdout: stdout.slice(0, 500) }, 'bytedcli poll: no parsable JSON, treating as expired');
    return { loginStatus: 'expired' };
  }

  if (result.status === 'error') {
    const code = (result.error as { code?: string })?.code ?? '';
    // CHALLENGE_EXPIRED 等错误码 → expired；其它未知 error 也按 expired 处理避免死循环
    logger.info(
      { userId, code, error: result.error },
      'bytedcli poll: error status, treating as expired',
    );
    return { loginStatus: 'expired' };
  }

  const data = result.data as { login_status?: string };
  if (data?.login_status === 'complete' || data?.login_status === 'completed') {
    return {
      loginStatus: 'complete',
      authedDataDir: getUserBytedcliDataDir(userId, dataDir),
    };
  }
  if (data?.login_status === 'expired') {
    return { loginStatus: 'expired' };
  }
  // pending / 其它未知都按 pending 处理
  return { loginStatus: 'pending' };
}

/**
 * 检查 user sandbox 是否已有可用的 authed 数据（bytecloud-auth/ 存在）。
 * 用于：① 启动时校验 authed user 的 sandbox 是否还在 ② mount 前 sanity check
 */
export function hasAuthedSandbox(userId: string, dataDir: string): boolean {
  const sandboxData = getUserBytedcliDataDir(userId, dataDir);
  // bytecloud-auth/ 是 authed 后必有的目录（实测）
  return fs.existsSync(path.join(sandboxData, 'bytecloud-auth'));
}
