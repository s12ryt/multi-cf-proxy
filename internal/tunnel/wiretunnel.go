package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"multi-cf-proxy/internal/config"
)

// warpMTU WARP 隧道內層 MTU（IPv6 安全下限，外層由 WireGuard 封裝）。
const warpMTU = 1280

// warpDNS 隧道內使用的 DNS（經 WARP 出口解析，避免本機 DNS 洩漏）。
var warpDNS = []netip.Addr{
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("2606:4700:4700::1111"),
}

// DefaultDNSCacheSeconds 經隧道 DNS 結果的默認本機快取秒數。
const DefaultDNSCacheSeconds = 60

// wireTunnel 用戶態 WireGuard 隧道（wireguard-go + gVisor netstack）。
type wireTunnel struct {
	id          string
	privateHex  string
	peerHex     string
	endpoint    string // 配置中的 endpoint（可為域名）
	fingerprint string
	localAddrs  []netip.Addr

	mu               sync.Mutex
	dev              *device.Device
	net              *netstack.Net
	resolvedEndpoint string    // 每次 Start/Rebuild 重新解析出的 IP:port
	dns              *dnsCache // 經隧道解析結果的本機快取（消除重複 DNS 往返）
}

// dnsTTLSetter 可接收 DNS 快取 TTL 的隧道（Manager 運行時傳播）。
type dnsTTLSetter interface {
	SetDNSCacheTTL(d time.Duration) error
}

// WireFactory 正式隧道工廠：由上游配置建立用戶態 WireGuard 隧道。
func WireFactory(u *config.Upstream) (Tunnel, error) {
	privHex, err := keyB64ToHex(u.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("上游 %s（%s）私鑰無效: %w", u.ID, u.Name, err)
	}
	peerHex, err := keyB64ToHex(u.PeerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("上游 %s（%s）對端公鑰無效: %w", u.ID, u.Name, err)
	}
	var addrs []netip.Addr
	for _, a := range u.Addresses {
		ipPart, _, found := strings.Cut(a, "/")
		if !found {
			ipPart = a
		}
		ip, err := netip.ParseAddr(ipPart)
		if err != nil {
			return nil, fmt.Errorf("上游 %s（%s）隧道地址無效 %q: %w", u.ID, u.Name, a, err)
		}
		addrs = append(addrs, ip.Unmap())
	}
	w := &wireTunnel{
		id:          u.ID,
		privateHex:  privHex,
		peerHex:     peerHex,
		endpoint:    u.Endpoint,
		localAddrs:  addrs,
		fingerprint: fingerprint(u),
	}
	// 解析器綁定當前 netstack（Rebuild 後自動指向新實例）
	w.dns = newDNSCache(DefaultDNSCacheSeconds*time.Second, dnsCacheMaxEntries, func(ctx context.Context, host string) ([]string, error) {
		w.mu.Lock()
		tn := w.net
		w.mu.Unlock()
		if tn == nil {
			return nil, fmt.Errorf("隧道 %s 未運行", w.id)
		}
		return tn.LookupContextHost(ctx, host)
	})
	return w, nil
}

// SetDNSCacheTTL 調整本隧道的 DNS 快取 TTL（0 = 停用；Manager 傳播調用）。
func (w *wireTunnel) SetDNSCacheTTL(d time.Duration) error {
	w.dns.setTTL(d)
	return nil
}

func keyB64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", fmt.Errorf("base64 解碼失敗: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("金鑰長度應為 32 位元組, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// lookupHost 可注入的主機名解析（測試替換）；默認走系統解析器。
var lookupHost = net.LookupHost

// resolveEndpoint 把 endpoint 的主機名解析為 IP 字面值。
// 新版 wireguard-go 的 IpcSet 只接受 IP:port（netip.ParseAddrPort），
// 域名必須由調用方先解析（wg-quick 同此行為）。IP 字面值原樣返回。
func resolveEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint %q 不是 host:port: %w", endpoint, err)
	}
	if net.ParseIP(host) != nil {
		return endpoint, nil // 已是字面值（IPv4/IPv6）
	}
	ips, err := lookupHost(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("無法解析 endpoint 主機名 %s: %w", host, err)
	}
	return net.JoinHostPort(ips[0], port), nil
}

func (w *wireTunnel) ipcConfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", w.privateHex)
	fmt.Fprintf(&b, "public_key=%s\n", w.peerHex)
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	fmt.Fprintf(&b, "endpoint=%s\n", w.resolvedEndpoint)
	b.WriteString("persistent_keepalive_interval=25\n")
	return b.String()
}

// Start 建立底層 WireGuard 裝置並啟動（不等待握手完成）。
// endpoint 域名在此解析為 IP（每次啟動重新解析，IP 變動經 Rebuild 生效）。
func (w *wireTunnel) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dev != nil {
		return nil
	}
	ep, err := resolveEndpoint(w.endpoint)
	if err != nil {
		return fmt.Errorf("隧道 %s endpoint 解析失敗: %w", w.id, err)
	}
	w.resolvedEndpoint = ep
	tunDev, tnet, err := netstack.CreateNetTUN(w.localAddrs, warpDNS, warpMTU)
	if err != nil {
		return fmt.Errorf("隧道 %s 建立 netstack 失敗: %w", w.id, err)
	}
	logger := device.NewLogger(device.LogLevelError, "warp["+w.id+"] ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(w.ipcConfig()); err != nil {
		dev.Close()
		return fmt.Errorf("隧道 %s 配置無效: %w", w.id, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("隧道 %s 啟動失敗: %w", w.id, err)
	}
	w.dev = dev
	w.net = tnet
	return nil
}

// Stop 停止並釋放底層裝置。可重複呼叫。
func (w *wireTunnel) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dev != nil {
		w.dev.Close()
		w.dev = nil
		w.net = nil
	}
}

// Rebuild 原子地重建底層連接。
func (w *wireTunnel) Rebuild(ctx context.Context) error {
	w.Stop()
	return w.Start(ctx)
}

func (w *wireTunnel) ID() string { return w.id }

// Fingerprint 返回建立時快取的配置指紋。
func (w *wireTunnel) Fingerprint() string { return w.fingerprint }

// DialContext 經隧道撥號（TCP）。IP 字面值直連；域名先查本隧道的
// DNS 快取（TTL 內免往返），未命中才經 WARP 解析；候選位址依序嘗試。
func (w *wireTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("隧道 %s 不支援的網絡類型 %q", w.id, network)
	}
	w.mu.Lock()
	tnet := w.net
	cache := w.dns
	w.mu.Unlock()
	if tnet == nil {
		return nil, fmt.Errorf("隧道 %s 未運行", w.id)
	}

	candidates, err := resolveTarget(ctx, cache, addr)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ap := range candidates {
		conn, derr := tnet.DialContextTCPAddrPort(ctx, ap)
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("隧道 %s 撥號 %s 失敗: %w", w.id, addr, lastErr)
}
