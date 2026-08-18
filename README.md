# 多開CF代理（multi-cf-proxy）

[![CI](https://github.com/s12ryt/multi-cf-proxy/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Release](https://github.com/s12ryt/multi-cf-proxy/actions/workflows/release.yml/badge.svg)](../../actions/workflows/release.yml)

**繁體中文** | [简体中文](README.zh-CN.md) | [English](README.en.md)

在 VPS 上自管**多條 Cloudflare WARP 用戶態隧道**，對外提供 SOCKS5 與 HTTP 入站代理。
**每組帳密綁定一條 WARP 出口**（不同帳密 = 不同出口 IP），附 Web 管理界面，
支持主動健康檢查、隧道自動重建、出口故障自動切換與流量統計。

## 特性

- **多 WARP 實例**：用戶態 WireGuard（wireguard-go + gVisor netstack），無需 TUN 設備、無需 root
- **雙協議入站**：SOCKS5（RFC 1928/1929，僅帳密認證）與 HTTP 代理（Basic + CONNECT），各一端口
- **帳密綁出口**：每新增上游自動分配「隨機用戶名 + 隨機密碼」；綁定出口不健康時自動 failover 到其他健康出口
- **全自動重連**：週期健康探測（經隧道訪問 Cloudflare trace）→ 連續失敗達閾值 → 標記不健康並自動重建隧道 → 恢復後自動回到健康池
- **流量統計**：每帳號 / 每上游的上下行位元組數，IPv4 / IPv6 分開
- **Web 管理**：管理員密碼登入（session），上游增刪改、WARP 帳號自動註冊、手動導入 wgcf 配置、換帳密、設置、統計
- **單二進制**：Go 編寫，交叉編譯 Linux amd64/arm64，無執行時依賴

## 一鍵安裝（Linux + systemd，推薦）

```bash
curl -fsSL https://raw.githubusercontent.com/s12ryt/multi-cf-proxy/main/deploy/install.sh | sudo bash
```

腳本自動：探測架構（amd64/arm64）→ 從 Releases 下載最新版 → sha256 校驗 →
安裝二進制與 systemd 服務 → 啟動並設開機自啟 → 印出管理員密碼。

- 指定版本：`... | sudo VERSION=v1.0.0 bash`
- 解除安裝：`... | sudo bash -s -- --uninstall`

### 手動安裝（替代）

從 [Releases](../../releases) 下載對應架構的二進制（v1.2.0 起佈局：程序與配置統一在 `/etc/multi-cf-proxy`，不安裝到 /usr）：

```bash
sudo install -d -o multi-cf-proxy -g multi-cf-proxy -m 750 /etc/multi-cf-proxy
sudo install -m 755 multi-cf-proxy-linux-amd64 /etc/multi-cf-proxy/multi-cf-proxy
sudo useradd --system -d /etc/multi-cf-proxy -s /usr/sbin/nologin -M multi-cf-proxy 2>/dev/null || true
sudo cp deploy/systemd/multi-cf-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now multi-cf-proxy
sudo journalctl -u multi-cf-proxy | grep 管理員密碼   # 首次生成的密碼
```

打開 `http://<VPS>:8081` 登入後：

1. **自動註冊**：輸入數量 → 一鍵註冊 WARP 帳號（被 CF 風控時改用手動導入）
2. **手動導入**：貼上 `wgcf` 生成的 WireGuard 配置全文
3. 頁面會彈出該上游的 `用戶名:密碼` —— **請立即保存**（密碼僅此一次完整顯示）

## 自行構建

```bash
# Linux / macOS / Windows（Go ≥ 1.26）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o multi-cf-proxy .

# Windows PowerShell
./build.ps1
```

## Docker（GHCR 鏡像）

```bash
docker run -d --name mcp \
  -p 1080:1080 -p 8080:8080 -p 8081:8081 \
  -v /srv/mcp:/config \
  ghcr.io/s12ryt/multi-cf-proxy:latest
docker logs mcp 2>&1 | grep 管理員密碼   # 首次生成的密碼
```

鏡像 `ghcr.io/s12ryt/multi-cf-proxy` 由 CI 自動構建並推送，支持
`linux/amd64` 與 `linux/arm64`；標籤：`latest`、`1.0`（major.minor）、`1.0.0`（完整版本）。
也可以從原始碼自建：`docker build -f deploy/Dockerfile -t multi-cf-proxy .`

## 客戶端使用

| 服務 | 地址 | 認證 |
|---|---|---|
| SOCKS5 | `<VPS>:1080` | Web 頁顯示的 `用戶名:密碼` |
| HTTP 代理 | `<VPS>:8080` | 同上（Basic） |

示例：

```bash
curl -x socks5h://warp-xxxx:PASSWORD@VPS:1080 https://www.cloudflare.com/cdn-cgi/trace
curl -x http://warp-xxxx:PASSWORD@VPS:8080 https://www.cloudflare.com/cdn-cgi/trace
# trace 輸出中 warp=on 即代表流量已走 WARP
```

不同帳密 → 不同 WARP 出口 IP；出口故障時自動切換其他健康出口並重試。

## 配置文件（單一 JSON，默認 `config.json`）

```json
{
  "admin_password": "…首次啟動自動生成…",
  "listen_socks5": ":1080",
  "listen_http": ":8080",
  "listen_web": ":8081",
  "dns_cache_seconds": 60,
  "health_check": { "interval_seconds": 30, "failure_threshold": 3, "latency_discard_seconds": 0, "latency_probe_seconds": 0 },
  "upstreams": [
    {
      "id": "uXXXXXXXX",
      "name": "warp-ab12",
      "enabled": true,
      "private_key": "…base64…",
      "peer_public_key": "…base64…",
      "endpoint": "engage.cloudflareclient.com:2408",
      "addresses": ["172.16.0.2/32", "2606:4700:110:8e12::/128"],
      "account": { "username": "warp-ab12", "password": "…" }
    }
  ]
}
```

Web 上的所有修改即時寫盤（原子寫入）；端口與健康參數修改後重啟生效。

## 架構

```
main.go ─ 組裝與信號處理
internal/config     JSON 配置 + Manager（併發安全、事務式更新）
internal/warp       WARP 註冊 API 客戶端 + wgcf 配置解析 + 金鑰生成
internal/tunnel     隧道管理：健康狀態機、自動重建、wireguard-go/gVisor 用戶態隧道
internal/auth       帳號索引：常數時間密碼校驗
internal/stats      流量計數（併發安全，v4/v6 × 上/下行）
internal/dispatcher 鑑權 + 選路（綁定優先、failover 重試）
internal/inbound    SOCKS5 / HTTP 入站服務器
internal/web        管理 API（session）+ 嵌入式前端
```

## 已知限制

- SOCKS5 UDP ASSOCIATE 不支持（僅 TCP CONNECT）
- WARP 自動註冊依賴 Cloudflare API 可用性；被風控時請用 wgcf 手動註冊後導入配置
- 端口 / 健康參數修改需重啟生效
- 帳號密碼僅在生成時完整顯示一次（概覽頁不回顯）

## 開發

```bash
go test ./...     # 全部測試
go vet ./...
```

## 授權

[MIT](LICENSE)
