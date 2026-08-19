# 多开CF代理（multi-cf-proxy）

[![CI](https://github.com/s12ryt/multi-cf-proxy/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Release](https://github.com/s12ryt/multi-cf-proxy/actions/workflows/release.yml/badge.svg)](../../actions/workflows/release.yml)

[繁體中文](README.md) | **简体中文** | [English](README.en.md)

在 VPS 上自管**多条 Cloudflare WARP 用户态隧道**，对外提供 SOCKS5 与 HTTP 入站代理。
**每组账号密码绑定一条 WARP 出口**（不同账号密码 = 不同出口 IP），附 Web 管理界面，
支持主动健康检查、隧道自动重建、出口故障自动切换与流量统计。

## 特性

- **多 WARP 实例**：用户态 WireGuard（wireguard-go + gVisor netstack），无需 TUN 设备、无需 root
- **双协议入站**：SOCKS5（RFC 1928/1929，仅账号密码认证）与 HTTP 代理（Basic + CONNECT），各一端口
- **账号绑出口**：每新增上游自动分配「随机用户名 + 随机密码」；绑定出口不健康时自动 failover 到其他健康出口
- **延迟优选**：备援按探测延迟排序（快者先试；延迟经 EMA 平滑）；可选「全局延迟优先」模式——取健康上游清单、一律走当前延迟最低的健康出口（拨号失败依延迟序降级）
- **全自动重连**：周期健康探测（经隧道直连 1.1.1.1 trace；keep-alive 稳态计时 ≈1×RTT 贴近实际连线体验，冷连接路径每轮仍完整验证）→ 连续失败达阈值 → 标记不健康并自动重建隧道 → 恢复后自动回到健康池
- **流量统计**：每账号 / 每上游的上下行字节数，IPv4 / IPv6 分开
- **Web 管理**：管理员密码登录（session），上游增删改、WARP 账号自动注册、手动导入 wgcf 配置、换账号密码、设置、统计
- **单一二进制**：Go 编写，交叉编译 Linux amd64/arm64，无运行时依赖

## 一键安装（Linux + systemd，推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/s12ryt/multi-cf-proxy/main/deploy/install.sh | sudo bash
```

脚本自动：探测架构（amd64/arm64）→ 从 Releases 下载最新版 → sha256 校验 →
安装二进制与 systemd 服务 → 启动并设开机自启 → 打印管理员密码。

- 指定版本：`... | sudo VERSION=v1.0.0 bash`
- 卸载：`... | sudo bash -s -- --uninstall`

### 手动安装（替代）

从 [Releases](../../releases) 下载对应架构的二进制（v1.2.0 起布局：程序与配置统一在 `/etc/multi-cf-proxy`，不安装到 /usr）：

```bash
sudo install -d -o multi-cf-proxy -g multi-cf-proxy -m 750 /etc/multi-cf-proxy
sudo install -m 755 multi-cf-proxy-linux-amd64 /etc/multi-cf-proxy/multi-cf-proxy
sudo useradd --system -d /etc/multi-cf-proxy -s /usr/sbin/nologin -M multi-cf-proxy 2>/dev/null || true
sudo cp deploy/systemd/multi-cf-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now multi-cf-proxy
sudo journalctl -u multi-cf-proxy | grep 管理员密码   # 首次生成的密码
```

打开 `http://<VPS>:8081` 登录后：

1. **自动注册**：输入数量 → 一键注册 WARP 账号（被 CF 风控时改用手动导入）
2. **手动导入**：粘贴 `wgcf` 生成的 WireGuard 配置全文
3. 页面会弹出该上游的 `用户名:密码` —— **请立即保存**（密码仅此一次完整显示）

## 自行构建

```bash
# Linux / macOS / Windows（Go ≥ 1.26）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o multi-cf-proxy .

# Windows PowerShell
./build.ps1
```

## Docker（GHCR 镜像）

```bash
docker run -d --name mcp \
  -p 1080:1080 -p 8080:8080 -p 8081:8081 \
  -v /srv/mcp:/config \
  ghcr.io/s12ryt/multi-cf-proxy:latest
docker logs mcp 2>&1 | grep 管理员密码   # 首次生成的密码
```

镜像 `ghcr.io/s12ryt/multi-cf-proxy` 由 CI 自动构建并推送，支持
`linux/amd64` 与 `linux/arm64`；标签：`latest`、`1.0`（major.minor）、`1.0.0`（完整版本）。
也可以从源码自建：`docker build -f deploy/Dockerfile -t multi-cf-proxy .`

## 客户端使用

| 服务 | 地址 | 认证 |
|---|---|---|
| SOCKS5 | `<VPS>:1080` | Web 页显示的 `用户名:密码` |
| HTTP 代理 | `<VPS>:8080` | 同上（Basic） |

示例：

```bash
curl -x socks5h://warp-xxxx:PASSWORD@VPS:1080 https://www.cloudflare.com/cdn-cgi/trace
curl -x http://warp-xxxx:PASSWORD@VPS:8080 https://www.cloudflare.com/cdn-cgi/trace
# trace 输出中 warp=on 即代表流量已走 WARP
```

不同账号密码 → 不同 WARP 出口 IP；出口故障时自动切换其他健康出口并重试。

## 配置文件（单一 JSON，默认 `config.json`）

```json
{
  "admin_password": "…首次启动自动生成…",
  "listen_socks5": ":1080",
  "listen_http": ":8080",
  "listen_web": ":8081",
  "dns_cache_seconds": 60,
  "routing": { "prefer_lowest_latency": false },
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

Web 上的所有修改即时写盘（原子写入）并**即时生效**——含端口（热切换：先绑新再关旧，失败沿用旧地址）、健康参数、DNS 缓存与延迟优选；仅变更 Web 监听地址后需以新地址重新打开管理页。

## 架构

```
main.go ─ 组装与信号处理
internal/config     JSON 配置 + Manager（并发安全、事务式更新）
internal/warp       WARP 注册 API 客户端 + wgcf 配置解析 + 密钥生成
internal/tunnel     隧道管理：健康状态机、自动重建、wireguard-go/gVisor 用户态隧道
internal/auth       账号索引：常数时间密码校验
internal/stats      流量计数（并发安全，v4/v6 × 上/下行）
internal/dispatcher 鉴权 + 选路（绑定优先、failover 重试）
internal/inbound    SOCKS5 / HTTP 入站服务器
internal/web        管理 API（session）+ 嵌入式前端
```

## 已知限制

- SOCKS5 UDP ASSOCIATE 不支持（仅 TCP CONNECT）
- WARP 自动注册依赖 Cloudflare API 可用性；被风控时请用 wgcf 手动注册后导入配置
- 全局延迟优先模式下出口 IP 会随延迟漂移而变（需 IP 稳定的网站 session 请保持关闭）
- 账号密码仅在生成时完整显示一次（概览页不回显）

## 开发

```bash
go test ./...     # 全部测试
go vet ./...
```

## 授权

[MIT](LICENSE)
