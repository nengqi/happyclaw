#!/usr/bin/env bash
# happyclaw B 方案 · 傻瓜登录脚本
# ─────────────────────────────────────────────────────────────────────────────
# 同事在自己机器上跑（合规：用本人身份在本机浏览器走 账号+密码/passkey 登录
# bytedcli），脚本自动拿 codebase PAT + bytecloud JWT，并自动回传到 happyclaw。
# 密钥全程不进飞书对话（对话里只出现一次性 nonce）。
#
# 用法（happyclaw /login 会生成这一行直接发给你）：
#   curl -fsSL https://bytedcli-login.gf-preview.bytedance.net/login.sh | bash -s -- <nonce>
#
# 可选 env：
#   BYTEDCLI_SITE     默认 i18n-tt（codebase 跨 site 统一，i18n 凭证能拉 cn 代码）
#   MACMINI_IP        手动指定 happyclaw 主机 IP（跳过自动探测）
#   HAPPYCLAW_PORT    默认 3000
#   IPS_URL           Mac mini IP 发布页（默认 gecsearch-macmini-ip 的 /ips.txt）
set -euo pipefail

NONCE="${1:-${NONCE:-}}"
SITE="${BYTEDCLI_SITE:-i18n-tt}"
PORT="${HAPPYCLAW_PORT:-3000}"
IPS_URL="${IPS_URL:-https://gecsearch-macmini-ip.gf-preview.bytedance.net/ips.txt}"

say() { printf '\033[36m[happyclaw-login]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[happyclaw-login] ✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ -n "$NONCE" ] || die "缺 nonce。请用 happyclaw /login 生成的整行命令运行。"
command -v bytedcli >/dev/null 2>&1 || die "未装 bytedcli：npm i -g @bytedance-dev/bytedcli --registry https://bnpm.byted.org"
command -v python3 >/dev/null 2>&1 || die "未装 python3"

# 1) 确保本机已登录 bytedcli（本人身份，本机浏览器走合规登录方式）
if ! bytedcli --site "$SITE" auth status >/dev/null 2>&1; then
  say "未登录，拉起 bytedcli 登录（在弹出的浏览器里用你本人账号完成）..."
  bytedcli --site "$SITE" auth login
fi
say "bytedcli 已登录 ($SITE)"

# 2) 自助创建 codebase PAT（90 天，长效，自包含不绑 device key → 可跨机回传）
say "创建 codebase PAT..."
PAT_JSON="$(bytedcli --site "$SITE" codebase pat create \
  --name "happyclaw-$(date +%m%d%H%M)" \
  --scopes "repo.content:read,repo:download" \
  --json 2>/dev/null || true)"

# 3) 拿 bytecloud JWT（短效，给容器内 bytedcli 命令用；best-effort）
say "获取 bytecloud JWT..."
JWT_JSON="$(bytedcli --site "$SITE" auth get-bytecloud-jwt-token --json 2>/dev/null || true)"

# 4) 解析 + 探测 happyclaw 主机 IP + 回传（python3 一把梭，JSON 处理稳）
say "回传凭证到 happyclaw..."
PAT_JSON="$PAT_JSON" JWT_JSON="$JWT_JSON" NONCE="$NONCE" PORT="$PORT" \
  MACMINI_IP="${MACMINI_IP:-}" IPS_URL="$IPS_URL" python3 - <<'PY'
import json, os, sys, urllib.request, urllib.error

def parse_last_json(s):
    """bytedcli --json 末行是 {...}（status 字段）；取最后一个能解析的 JSON 行。"""
    for line in reversed((s or "").strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except Exception:
                continue
    return {}

pat_raw = parse_last_json(os.environ.get("PAT_JSON", ""))
jwt_raw = parse_last_json(os.environ.get("JWT_JSON", ""))
pat_data = pat_raw.get("data", pat_raw) if isinstance(pat_raw, dict) else {}
jwt_data = jwt_raw.get("data", jwt_raw) if isinstance(jwt_raw, dict) else {}

pat = pat_data.get("token", "") if isinstance(pat_data, dict) else ""
pab = (pat_data.get("personal_access_token") or {}) if isinstance(pat_data, dict) else {}
pat_id = pab.get("Id") or pab.get("id") or ""
pat_exp = pat_data.get("expires_at", "") if isinstance(pat_data, dict) else ""
jwt = jwt_data.get("token", "") if isinstance(jwt_data, dict) else ""
host = jwt_data.get("host", "") if isinstance(jwt_data, dict) else ""

if not pat and not jwt:
    sys.exit("✗ 没拿到 PAT 或 JWT（bytedcli 输出异常，重跑或检查登录态）")

body = json.dumps({
    "nonce": os.environ["NONCE"],
    "pat": pat, "patId": pat_id, "patExpiresAt": pat_exp,
    "bytecloudJwt": jwt, "cloudHost": host,
}).encode()

# 候选 IP：手动 MACMINI_IP 优先，否则从 /ips.txt 取 10.x/172.x/192.168.x active
candidates = []
manual = os.environ.get("MACMINI_IP", "").strip()
if manual:
    candidates = [manual]
else:
    try:
        txt = urllib.request.urlopen(os.environ["IPS_URL"], timeout=12).read().decode()
        for line in txt.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].split(".")[0] in ("10", "172", "192") and "169.254" not in parts[1]:
                if len(parts) < 3 or parts[2] == "active":
                    candidates.append(parts[1])
    except Exception as e:
        sys.exit(f"✗ 取 Mac mini IP 失败：{e}（可设 MACMINI_IP 手动指定）")

if not candidates:
    sys.exit("✗ 没找到可达的 happyclaw 主机 IP")

port = os.environ["PORT"]
last_err = ""
for ip in candidates:
    url = f"http://{ip}:{port}/bytedcli/upload"
    try:
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"✓ 回传成功 → {ip}:{port}  (PAT={'yes' if pat else 'no'} JWT={'yes' if jwt else 'no'})")
            sys.exit(0)
    except Exception as e:
        last_err = f"{ip}: {e}"
        continue

sys.exit(f"✗ 所有候选 IP 回传失败，最后错误：{last_err}")
PY

say "完成 ✓ 回飞书发任意消息，容器会用你本人身份跑。"
