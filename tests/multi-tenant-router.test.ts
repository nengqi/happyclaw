/**
 * Multi-tenant（shared bot）sender 路由 + auto-register 测试。
 *
 * 验证核心行为（fork: 多租户路由，适配 upstream c9757d5）：
 *   ① 两个不同 senderOpenId 各自路由到不同的 happyclaw userId（且 home folder 不同）
 *   ② 全新 senderOpenId 首次出现触发 auto-register（建新 member user + home）
 *   ③ 两个 sender 的 chatJid → folder 绑定互不串扰
 *   ④ ★ auto-register 的 member home 必须是 container（Docker 沙盒）执行模式，绝不是 host
 *
 * 测试直接打到真实 db 层（与其它 db 测试同风格：mock config.js 把 DB 隔离到临时目录）。
 * ensureFeishuUser / sender 路由的编排逻辑在 index.ts，但 index.ts 在 import 时会 main()
 * 起服务无法直接引入，故在此忠实复刻其对 db 原语的调用顺序，复用与生产同一组 exported db
 * 函数验证行为。
 */
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

// Isolate DB + groups to a temp dir (config.js is the single source for these paths)
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'multi-tenant-test-'));
const tmpStoreDir = path.join(tmpDir, 'db');
const tmpGroupsDir = path.join(tmpDir, 'groups');
fs.mkdirSync(tmpStoreDir, { recursive: true });
fs.mkdirSync(tmpGroupsDir, { recursive: true });

vi.mock('../src/config.js', async () => {
  return {
    STORE_DIR: tmpStoreDir,
    GROUPS_DIR: tmpGroupsDir,
    MAIN_GROUP_FOLDER: 'main',
  };
});

const {
  initDatabase,
  createUser,
  getUserById,
  getUserByFeishuOpenId,
  setUserFeishuOpenId,
  setUserEnabledSkills,
  ensureUserHomeGroup,
  getUserHomeGroup,
  getUserCount,
  setRegisteredGroup,
  getRegisteredGroup,
} = await import('../src/db.js');

beforeAll(() => {
  initDatabase();
});

afterAll(() => {
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

// ── Faithful replica of index.ts ensureFeishuUser ──
// 已存在 → 返回；不存在 → 建 member user + 绑 feishu_open_id + 默认 skills + ensureUserHomeGroup。
// ★ 沙盒隔离：role='member' 让 ensureUserHomeGroup 走 container 默认（绝不传 'admin'）。
const DEFAULT_SKILLS = ['feishu', 'eat'];
function ensureFeishuUser(openId: string, displayName: string): string {
  const existing = getUserByFeishuOpenId(openId);
  if (existing) return existing.id;

  const now = new Date().toISOString();
  const userId = crypto.randomUUID();
  const baseName = `feishu_${openId.replace(/[^A-Za-z0-9_-]/g, '').slice(-8)}`;
  createUser({
    id: userId,
    username: baseName,
    password_hash: 'x'.repeat(20),
    display_name: displayName || baseName,
    role: 'member',
    status: 'active',
    created_at: now,
    updated_at: now,
  });
  setUserFeishuOpenId(userId, openId);
  setUserEnabledSkills(userId, DEFAULT_SKILLS);
  // member → ensureUserHomeGroup 默认建 container 执行模式的 home（沙盒），不设 host
  ensureUserHomeGroup(userId, 'member', displayName || baseName);
  return userId;
}

// ── Faithful replica of index.ts buildOnSenderRoute(adminUserId) ──
// 解析/创建 user → 把 chatJid 绑定到该 user 的 home folder（created_by=admin 让出站回复走共享 bot）
const ADMIN_USER_ID = 'admin-shared-bot';
function routeSender(
  senderOpenId: string,
  senderName: string,
  chatJid: string,
): string | null {
  const userId = ensureFeishuUser(senderOpenId, senderName);
  const home = getUserHomeGroup(userId);
  const homeFolder = home?.folder ?? `home-${userId}`;
  const existing = getRegisteredGroup(chatJid);
  if (
    !existing ||
    existing.folder !== homeFolder ||
    existing.created_by !== ADMIN_USER_ID
  ) {
    setRegisteredGroup(chatJid, {
      name: existing?.name || `${senderName} (飞书)`,
      folder: homeFolder,
      added_at: existing?.added_at ?? new Date().toISOString(),
      created_by: ADMIN_USER_ID,
      is_home: false,
    });
  }
  return userId;
}

describe('multi-tenant shared bot: sender 路由 + auto-register', () => {
  test('① 两个不同 senderOpenId 路由到不同 user + 不同 home folder', () => {
    const aId = routeSender('ou_alice', 'Alice', 'feishu:p2p_alice');
    const bId = routeSender('ou_bob', 'Bob', 'feishu:p2p_bob');

    expect(aId).toBeTruthy();
    expect(bId).toBeTruthy();
    expect(aId).not.toBe(bId);

    const aFolder = getUserHomeGroup(aId!)?.folder;
    const bFolder = getUserHomeGroup(bId!)?.folder;
    expect(aFolder).toBe(`home-${aId}`);
    expect(bFolder).toBe(`home-${bId}`);
    expect(aFolder).not.toBe(bFolder);
  });

  test('② 全新 senderOpenId 触发 auto-register（新建 user + 可被反查）', () => {
    const before = getUserCount();
    expect(getUserByFeishuOpenId('ou_carol')).toBeUndefined();

    const cId = routeSender('ou_carol', 'Carol', 'feishu:p2p_carol');

    expect(getUserCount()).toBe(before + 1);
    const carol = getUserByFeishuOpenId('ou_carol');
    expect(carol).toBeDefined();
    expect(carol!.id).toBe(cId);
    expect(carol!.role).toBe('member');
    expect(carol!.feishu_open_id).toBe('ou_carol');
    expect(carol!.enabled_skills).toEqual(DEFAULT_SKILLS);
    // home 容器已建立
    expect(getUserHomeGroup(cId!)?.folder).toBe(`home-${cId}`);
  });

  test('②b 已存在 sender 二次发消息不重复建 user（幂等）', () => {
    const firstId = getUserByFeishuOpenId('ou_alice')!.id;
    const before = getUserCount();
    const againId = routeSender('ou_alice', 'Alice', 'feishu:p2p_alice');
    expect(againId).toBe(firstId);
    expect(getUserCount()).toBe(before); // 没有新建
  });

  test('③ 两个 sender 的 chatJid → folder 绑定互不串扰', () => {
    const aId = getUserByFeishuOpenId('ou_alice')!.id;
    const bId = getUserByFeishuOpenId('ou_bob')!.id;

    const aBinding = getRegisteredGroup('feishu:p2p_alice');
    const bBinding = getRegisteredGroup('feishu:p2p_bob');

    // 各自指向自己 sender 的 home folder
    expect(aBinding?.folder).toBe(`home-${aId}`);
    expect(bBinding?.folder).toBe(`home-${bId}`);
    expect(aBinding?.folder).not.toBe(bBinding?.folder);

    // 出站回复经共享 bot：两条绑定的 created_by 都是 admin（IM 连接 owner）
    expect(aBinding?.created_by).toBe(ADMIN_USER_ID);
    expect(bBinding?.created_by).toBe(ADMIN_USER_ID);

    // Alice 再发一条消息，不会污染 Bob 的绑定
    routeSender('ou_alice', 'Alice', 'feishu:p2p_alice');
    expect(getRegisteredGroup('feishu:p2p_bob')?.folder).toBe(`home-${bId}`);
  });

  test('④ ★ auto-register 的 member home 是 container（Docker 沙盒），绝不是 host', () => {
    const dId = routeSender('ou_dave', 'Dave', 'feishu:p2p_dave');
    const home = getUserHomeGroup(dId!);
    expect(home).toBeDefined();
    // 核心诉求：member home 走容器执行模式，Agent 删文件只影响容器、不碰宿主机。
    expect(home!.executionMode).toBe('container');
    expect(home!.folder).not.toBe('main'); // 不复用 admin 的 host main 容器
  });

  test('admin 预设 feishu_open_id 时 P2P 命中 admin 自己（不 auto-register）', () => {
    // admin 手填 feishu_open_id 到自己 user（启动兜底回填模拟）
    const adminNow = new Date().toISOString();
    createUser({
      id: ADMIN_USER_ID,
      username: 'admin',
      password_hash: 'x'.repeat(20),
      display_name: 'Admin',
      role: 'admin',
      status: 'active',
      created_at: adminNow,
      updated_at: adminNow,
    });
    setUserFeishuOpenId(ADMIN_USER_ID, 'ou_admin_self');
    ensureUserHomeGroup(ADMIN_USER_ID, 'admin', 'admin');

    const before = getUserCount();
    const routed = routeSender('ou_admin_self', 'Admin', 'feishu:p2p_admin');
    expect(routed).toBe(ADMIN_USER_ID);
    expect(getUserCount()).toBe(before); // 命中既有 admin，无新建
    // admin home = 'main'（host 模式）
    expect(getUserHomeGroup(ADMIN_USER_ID)?.folder).toBe('main');
    expect(getUserHomeGroup(ADMIN_USER_ID)?.executionMode).toBe('host');
    expect(getUserById(ADMIN_USER_ID)?.role).toBe('admin');
  });
});
