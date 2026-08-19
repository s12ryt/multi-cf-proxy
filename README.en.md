# Multi-CF-Proxy

[![CI](https://github.com/s12ryt/multi-cf-proxy/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![Release](https://github.com/s12ryt/multi-cf-proxy/actions/workflows/release.yml/badge.svg)](../../actions/workflows/release.yml)

[繁體中文](README.md) | [简体中文](README.zh-CN.md) | **English**

Run **multiple Cloudflare WARP userspace tunnels** on your VPS and expose them as
SOCKS5 and HTTP inbound proxies. **Each credential pair is bound to one WARP egress**
(different credentials = different egress IPs). Ships with a web admin UI,
active health checks, automatic tunnel rebuilds, egress failover and traffic accounting.

> Note: the web UI and log messages are in Traditional Chinese.

## Features

- **Multiple WARP instances**: userspace WireGuard (wireguard-go + gVisor netstack) — no TUN device, no root
- **Dual-protocol inbound**: SOCKS5 (RFC 1928/1929, username/password auth only) and HTTP proxy (Basic + CONNECT) on separate ports
- **Credential-bound egress**: every upstream gets an auto-generated random `username:password`; if the bound egress goes unhealthy, traffic fails over to other healthy egresses
- **Latency-preferred routing**: failover candidates are ordered by probe latency (fastest first; latency is EMA-smoothed so a one-off DNS/TLS jitter cannot cause egress flapping); optional "global lowest-latency" mode — each account sticks to the fastest healthy egress and only drifts when another egress is faster by more than the switch margin
- **Fully automatic reconnection**: periodic health probes (Cloudflare trace via tunnel) → consecutive failures reach threshold → marked unhealthy, tunnel auto-rebuilt → returns to the healthy pool once probes recover
- **Traffic accounting**: per-account / per-upstream up/down bytes, IPv4 / IPv6 separated
- **Web admin**: admin-password login (session), upstream CRUD, automatic WARP account registration, manual wgcf config import, credential regeneration, settings, stats
- **Single static binary**: written in Go, cross-compiles to Linux amd64/arm64, no runtime dependencies

## One-Click Install (Linux + systemd, recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/s12ryt/multi-cf-proxy/main/deploy/install.sh | sudo bash
```

The script automatically: detects architecture (amd64/arm64) → downloads the latest
release → verifies sha256 → installs the binary and systemd service → enables and
starts it → prints the admin password.

- Pin a version: `... | sudo VERSION=v1.0.0 bash`
- Uninstall: `... | sudo bash -s -- --uninstall`

### Manual Install (alternative)

Download the binary for your architecture from [Releases](../../releases)
(since v1.2.0 the layout keeps the binary and config together under
`/etc/multi-cf-proxy`; nothing is installed into /usr):

```bash
sudo install -d -o multi-cf-proxy -g multi-cf-proxy -m 750 /etc/multi-cf-proxy
sudo install -m 755 multi-cf-proxy-linux-amd64 /etc/multi-cf-proxy/multi-cf-proxy
sudo useradd --system -d /etc/multi-cf-proxy -s /usr/sbin/nologin -M multi-cf-proxy 2>/dev/null || true
sudo cp deploy/systemd/multi-cf-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now multi-cf-proxy
sudo journalctl -u multi-cf-proxy | grep "管理員密碼"   # password from first boot
```

Open `http://<VPS>:8081`, log in, then:

1. **Auto register**: enter a count → register WARP accounts in one click (fall back to manual import if Cloudflare rate-limits you)
2. **Manual import**: paste a full `wgcf`-generated WireGuard config
3. A `username:password` pair pops up for the new upstream — **save it immediately** (the password is shown in full only once)

## Building from Source

```bash
# Linux / macOS / Windows (Go ≥ 1.26)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o multi-cf-proxy .

# Windows PowerShell
./build.ps1
```

## Docker (GHCR image)

```bash
docker run -d --name mcp \
  -p 1080:1080 -p 8080:8080 -p 8081:8081 \
  -v /srv/mcp:/config \
  ghcr.io/s12ryt/multi-cf-proxy:latest
docker logs mcp 2>&1 | grep "管理員密碼"   # password generated on first boot
```

The `ghcr.io/s12ryt/multi-cf-proxy` image is built and pushed automatically by CI
for `linux/amd64` and `linux/arm64`; tags: `latest`, `1.0` (major.minor),
`1.0.0` (full version). You can also build from source:
`docker build -f deploy/Dockerfile -t multi-cf-proxy .`

## Client Usage

| Service | Address | Auth |
|---|---|---|
| SOCKS5 | `<VPS>:1080` | `username:password` shown by the web UI |
| HTTP proxy | `<VPS>:8080` | same (Basic) |

Examples:

```bash
curl -x socks5h://warp-xxxx:PASSWORD@VPS:1080 https://www.cloudflare.com/cdn-cgi/trace
curl -x http://warp-xxxx:PASSWORD@VPS:8080 https://www.cloudflare.com/cdn-cgi/trace
# warp=on in the trace output means traffic is going through WARP
```

Different credentials → different WARP egress IPs; when an egress fails, requests
automatically fail over to another healthy egress.

## Configuration (single JSON, default `config.json`)

```json
{
  "admin_password": "…auto-generated on first boot…",
  "listen_socks5": ":1080",
  "listen_http": ":8080",
  "listen_web": ":8081",
  "dns_cache_seconds": 60,
  "routing": { "prefer_lowest_latency": false, "switch_margin_ms": 20 },
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

Every change made in the web UI is persisted immediately (atomic writes) and
**applied at once** — including ports (hot swap: bind new listener first, close old
only on success; on failure the old address stays), health-check parameters, DNS
cache and latency-preferred routing. Only a changed web listen address requires
reopening the admin page at the new address.

## Architecture

```
main.go ─ wiring & signal handling
internal/config     JSON config + Manager (concurrency-safe, transactional updates)
internal/warp       WARP registration API client + wgcf config parsing + key generation
internal/tunnel     tunnel manager: health state machine, auto rebuild, wireguard-go/gVisor userspace tunnels
internal/auth       account index: constant-time password verification
internal/stats      traffic counters (concurrency-safe, v4/v6 × up/down)
internal/dispatcher auth + routing (bound egress first, failover retries)
internal/inbound    SOCKS5 / HTTP inbound servers
internal/web        admin API (session) + embedded frontend
```

## Known Limitations

- SOCKS5 UDP ASSOCIATE is not supported (TCP CONNECT only)
- Automatic WARP registration depends on Cloudflare API availability; when rate-limited, register manually with wgcf and import the config
- In global lowest-latency mode the egress IP drifts as latencies change (keep it off if you need a stable IP for website sessions)
- Account passwords are shown in full only once at generation time (never echoed on the overview page)

## Development

```bash
go test ./...     # full test suite
go vet ./...
```

## License

[MIT](LICENSE)
