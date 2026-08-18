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
- **全自动重连**：周期健康探测（经隧道访问 Cloudflare trace）→ 连续失败达阈值 → 标记不健康并自动重建隧道 → 恢复后自动回到健康池
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

从 [Releases](../../releases) 下载对应架构的二进制：

```bash
sudo cp multi-cf-proxy-linux-amd64 /usr/local/bin/multi-cf-proxy
sudo chmod +x /usr/local/bin/multi-cf-proxy
sudo mkdir -p /var/lib/multi-cf-proxy
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
  "health_check": { "interval_seconds": 30, "failure_threshold": 3 },
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

Web 上的所有修改即时写盘（原子写入）；端口与健康参数修改后重启生效。

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
- 端口 / 健康参数修改需重启生效
- 账号密码仅在生成时完整显示一次（概览页不回显）

## 开发

```bash
go test ./...     # 全部测试
go vet ./...
```

## 授权

[MIT](LICENSE)
