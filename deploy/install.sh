#!/bin/sh
# 多開CF代理（multi-cf-proxy）一鍵安裝腳本
# 適用：Linux amd64/arm64 + systemd（Debian/Ubuntu/Rocky/Arch 等主流發行版）
#
# 用法：
#   curl -fsSL https://raw.githubusercontent.com/s12ryt/multi-cf-proxy/main/deploy/install.sh | sudo bash
#   指定版本：curl -fsSL ... | sudo VERSION=v1.1.1 bash
#   解除安裝：curl -fsSL ... | sudo bash -s -- --uninstall
set -eu

REPO="s12ryt/multi-cf-proxy"
BIN="/usr/local/bin/multi-cf-proxy"
CONF_DIR="/var/lib/multi-cf-proxy"
PRIVATE_CONF_DIR="/var/lib/private/multi-cf-proxy"
SERVICE_FILE="/etc/systemd/system/multi-cf-proxy.service"
SERVICE_NAME="multi-cf-proxy"
SVC_USER="multi-cf-proxy"
VERSION="${VERSION:-}"

GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; OFF='\033[0m'
log() { printf "${GREEN}[multi-cf-proxy]${OFF} %s\n" "$*"; }
warn() { printf "${YELLOW}[警告]${OFF} %s\n" "$*"; }
err() { printf "${RED}[錯誤]${OFF} %s\n" "$*" >&2; }

# ---- 解除安裝 ----
if [ "${1:-}" = "--uninstall" ]; then
  [ "$(id -u)" -eq 0 ] || { err "請以 root 執行"; exit 1; }
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$BIN"
  systemctl daemon-reload 2>/dev/null || true
  if id "$SVC_USER" >/dev/null 2>&1; then
    userdel "$SVC_USER" 2>/dev/null || warn "無法刪除帳號 $SVC_USER（可能仍有進程佔用）"
  fi
  log "已解除安裝。配置目錄 $CONF_DIR（含帳密）保留，如確認不再使用請手動刪除："
  echo "  rm -rf $CONF_DIR"
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

# ---- 建立專用系統帳戶（不使用 DynamicUser：部分容器化 VPS 會 exec EACCES）----
if id "$SVC_USER" >/dev/null 2>&1; then
  log "系統帳號 $SVC_USER 已存在，沿用"
else
  useradd --system --home-dir "$CONF_DIR" --shell /usr/sbin/nologin --no-create-home "$SVC_USER"
  log "已建立系統帳號 $SVC_USER"
fi

# ---- 安裝二進制 ----
install -m 0755 "$TMP/$ASSET" "$BIN"

# ---- 執行權診斷（126 = 無法執行：多半是 noexec 掛載）----
EXEC_RC=0
runuser -u "$SVC_USER" -- "$BIN" -h >/dev/null 2>&1 || EXEC_RC=$?
if [ "$EXEC_RC" = "126" ]; then
  err "帳號 $SVC_USER 無法執行 $BIN（noexec 掛載？），請檢查：mount | grep noexec"
  err "或改用 Docker 部署（見 README）"
  exit 1
fi

# 清理 DynamicUser 時代遷移到 /var/lib/private 的殘留（若服務此前從未成功啟動、無配置）
if [ -d "$PRIVATE_CONF_DIR" ] && [ ! -e "$CONF_DIR/config.json" ] && [ ! -e "$PRIVATE_CONF_DIR/config.json" ]; then
  rm -rf "$PRIVATE_CONF_DIR" 2>/dev/null || true
fi

# ---- 安裝 systemd 服務 ----
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Multi-CF-Proxy (多開CF代理)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/multi-cf-proxy -config /var/lib/multi-cf-proxy/config.json
Restart=always
RestartSec=5
User=multi-cf-proxy
Group=multi-cf-proxy
StateDirectory=multi-cf-proxy
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
  log "服務已啟動並設為開機自啟"
else
  err "服務未正常啟動，請查看日誌：journalctl -u $SERVICE_NAME -e"
  exit 1
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
echo "  │ 配置文件 : $CONF_DIR/config.json"
echo "  │ 服務日誌 : journalctl -u multi-cf-proxy -f"
echo "  │ 解除安裝 : 再次執行本腳本加 --uninstall"
echo "  └──────────────────────────────────────────────────────"
