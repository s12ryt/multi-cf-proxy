#!/bin/sh
# 多開CF代理（multi-cf-proxy）一鍵安裝腳本
# 適用：Linux amd64/arm64 + systemd（Debian/Ubuntu/Rocky/Arch 等主流發行版）
#
# 佈局（v1.2.0 起，全面不使用 /usr 與 /var/lib）：
#   /etc/multi-cf-proxy/multi-cf-proxy   二進制（root:root 0755）
#   /etc/multi-cf-proxy/config.json      配置（服務帳戶可寫）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/s12ryt/multi-cf-proxy/main/deploy/install.sh | sudo bash
#   指定版本：curl -fsSL ... | sudo VERSION=v1.2.0 bash
#   解除安裝：curl -fsSL ... | sudo bash -s -- --uninstall
set -eu

REPO="s12ryt/multi-cf-proxy"
BASE_DIR="/etc/multi-cf-proxy"
BIN="$BASE_DIR/multi-cf-proxy"
SERVICE_FILE="/etc/systemd/system/multi-cf-proxy.service"
SERVICE_NAME="multi-cf-proxy"
SVC_USER="multi-cf-proxy"

# 舊版（<=v1.1.3）路徑，升級時遷移/清理
LEGACY_BIN="/usr/local/bin/multi-cf-proxy"
LEGACY_CONF_DIR="/var/lib/multi-cf-proxy"
LEGACY_PRIVATE_DIR="/var/lib/private/multi-cf-proxy"
VERSION="${VERSION:-}"

GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; OFF='\033[0m'
log() { printf "${GREEN}[multi-cf-proxy]${OFF} %s\n" "$*"; }
warn() { printf "${YELLOW}[警告]${OFF} %s\n" "$*"; }
err() { printf "${RED}[錯誤]${OFF} %s\n" "$*" >&2; }

# ---- 解除安裝 ----
if [ "${1:-}" = "--uninstall" ]; then
  [ "$(id -u)" -eq 0 ] || { err "請以 root 執行"; exit 1; }
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_FILE"
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$BASE_DIR"                                  # 二進制+配置（含帳密）
  rm -f "$LEGACY_BIN" 2>/dev/null || true             # 舊版二進制
  rm -rf "$LEGACY_CONF_DIR" "$LEGACY_PRIVATE_DIR" 2>/dev/null || true
  if id "$SVC_USER" >/dev/null 2>&1; then
    userdel "$SVC_USER" 2>/dev/null || warn "無法刪除帳號 $SVC_USER（可能仍有進程佔用）"
  fi
  log "已完全解除安裝（含配置與帳密）"
  exit 0
fi

# ---- 前置檢查 ----
[ "$(id -u)" -eq 0 ] || { err "請以 root 執行（加 sudo）"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) err "不支援的架構：$(uname -m)（僅支援 amd64/arm64）"; exit 1 ;;
esac

command -v systemctl >/dev/null 2>&1 || { err "此系統無 systemd，請改用 Docker 方式部署（見 README）"; exit 1; }
command -v curl >/dev/null 2>&1 || { err "缺少 curl，請先安裝（apt/yum install curl）"; exit 1; }
command -v useradd >/dev/null 2>&1 || { err "缺少 useradd；請改用 Docker 方式部署（見 README）"; exit 1; }

# 覆蓋安裝：先停掉可能在重啟循環中的舊服務
systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true

# ---- 解析版本（默認最新 release）----
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSL --retry 3 "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || { err "無法取得最新版本（GitHub API 不可達？）"; exit 1; }
fi
log "安裝版本 $VERSION（linux/$ARCH）"

# ---- 下載與校驗 ----
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ASSET="multi-cf-proxy-linux-$ARCH"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"

log "下載 $BASE_URL/$ASSET"
curl -fL --retry 3 -o "$TMP/$ASSET" "$BASE_URL/$ASSET"

if curl -fsSL --retry 2 -o "$TMP/checksums.txt" "$BASE_URL/checksums.txt" && [ -s "$TMP/checksums.txt" ]; then
  (cd "$TMP" && grep " $ASSET\$" checksums.txt | sha256sum -c -) \
    || { err "sha256 校驗失敗，檔案可能損壞"; exit 1; }
  log "sha256 校驗通過"
else
  warn "無法下載 checksums.txt，跳過校驗"
fi

# ---- 建立專用系統帳戶 ----
if id "$SVC_USER" >/dev/null 2>&1; then
  log "系統帳號 $SVC_USER 已存在，沿用"
else
  useradd --system --home-dir "$BASE_DIR" --shell /usr/sbin/nologin --no-create-home "$SVC_USER"
  log "已建立系統帳號 $SVC_USER"
fi

# ---- 安裝目錄與二進制（全部位於 /etc/multi-cf-proxy）----
mkdir -p "$BASE_DIR"
install -m 0755 -o root -g root "$TMP/$ASSET" "$BIN"
# 目錄歸服務帳戶（config.json 原子寫入需要目錄寫權）
chown "$SVC_USER:$SVC_USER" "$BASE_DIR"
chmod 750 "$BASE_DIR"

# ---- 舊版遷移與清理 ----
# 遷移配置（優先保留帳密）；DynamicUser 時代可能經由懸空 symlink 指向 private
if [ ! -e "$BASE_DIR/config.json" ]; then
  if [ -f "$LEGACY_CONF_DIR/config.json" ]; then
    cp "$LEGACY_CONF_DIR/config.json" "$BASE_DIR/config.json"
    chown "$SVC_USER:$SVC_USER" "$BASE_DIR/config.json"
    log "已遷移舊配置（帳密保留）"
  elif [ -f "$LEGACY_PRIVATE_DIR/config.json" ]; then
    cp "$LEGACY_PRIVATE_DIR/config.json" "$BASE_DIR/config.json"
    chown "$SVC_USER:$SVC_USER" "$BASE_DIR/config.json"
    log "已遷移舊配置（帳密保留，自 private 目錄）"
  fi
fi
# 清掉舊安裝位置（rm -rf 對 symlink 只刪連結本身）
rm -f "$LEGACY_BIN" 2>/dev/null || true
rm -rf "$LEGACY_PRIVATE_DIR" 2>/dev/null || true
[ -L "$LEGACY_CONF_DIR" ] && rm -f "$LEGACY_CONF_DIR"
[ -d "$LEGACY_CONF_DIR" ] && rmdir "$LEGACY_CONF_DIR" 2>/dev/null || true

# ---- 執行權診斷（126 = 無法執行：多半是 noexec 掛載）----
EXEC_RC=0
runuser -u "$SVC_USER" -- "$BIN" -h >/dev/null 2>&1 || EXEC_RC=$?
if [ "$EXEC_RC" = "126" ]; then
  err "帳號 $SVC_USER 無法執行 $BIN（noexec 掛載？），請檢查：mount | grep noexec"
  err "或改用 Docker 部署（見 README）"
  exit 1
fi

# ---- 安裝 systemd 服務（加固版失敗自動回退相容版）----
write_unit_hardened() {
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Multi-CF-Proxy (多開CF代理)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -config $BASE_DIR/config.json
Restart=always
RestartSec=5
User=$SVC_USER
Group=$SVC_USER
ReadWritePaths=$BASE_DIR
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
}

write_unit_compat() {
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Multi-CF-Proxy (多開CF代理)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -config $BASE_DIR/config.json
Restart=always
RestartSec=5
User=$SVC_USER
Group=$SVC_USER

[Install]
WantedBy=multi-user.target
EOF
}

svc_start_and_wait() {
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE_NAME" 2>/dev/null || true
  i=0
  while [ "$i" -lt 8 ]; do
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

write_unit_hardened
if svc_start_and_wait; then
  log "服務已啟動並設為開機自啟（沙箱加固模式）"
else
  warn "偵測到此環境不支援 systemd 沙箱選項（容器化 VPS 常見），改用相容模式…"
  write_unit_compat
  if svc_start_and_wait; then
    log "服務已啟動並設為開機自啟（相容模式，未啟用沙箱加固）"
  else
    err "服務仍無法啟動，最近日誌："
    journalctl -u "$SERVICE_NAME" --no-pager -n 10 2>/dev/null || true
    err "建議改用 Docker 部署：docker run -d --name mcp --restart unless-stopped -p 1080:1080 -p 8080:8080 -p 8081:8081 -v /srv/mcp:/config ghcr.io/s12ryt/multi-cf-proxy:latest"
    exit 1
  fi
fi

PW_HINT=$(journalctl -u "$SERVICE_NAME" --no-pager 2>/dev/null | grep -o '密碼[^ ]*: *[A-Za-z0-9_-]*' | tail -n1 || true)

echo ""
log "安裝完成！"
echo "  ┌──────────────────────────────────────────────────────"
echo "  │ 管理界面 : http://<本機IP>:8081"
if [ -n "$PW_HINT" ]; then
  echo "  │ $PW_HINT"
else
  echo "  │ 管理密碼 : journalctl -u multi-cf-proxy --no-pager | grep 管理員密碼"
fi
echo "  │ 程式與配置 : $BASE_DIR"
echo "  │ 服務日誌 : journalctl -u multi-cf-proxy -f"
echo "  │ 解除安裝 : 再次執行本腳本加 --uninstall"
echo "  └──────────────────────────────────────────────────────"
