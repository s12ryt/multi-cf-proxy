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

// wireTunnel 用戶態 WireGuard 隧道（wireguard-go + gVisor netstack）。
type wireTunnel struct {
	id          string
	privateHex  string
	peerHex     string
	endpoint    string
	localAddrs  []netip.Addr
	fingerprint string

	mu  sync.Mutex
	dev *device.Device
	net *netstack.Net
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
	return &wireTunnel{
		id:          u.ID,
		privateHex:  privHex,
		peerHex:     peerHex,
		endpoint:    u.Endpoint,
		localAddrs:  addrs,
		fingerprint: fingerprint(u),
	}, nil
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

func (w *wireTunnel) ipcConfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", w.privateHex)
	fmt.Fprintf(&b, "public_key=%s\n", w.peerHex)
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	fmt.Fprintf(&b, "endpoint=%s\n", w.endpoint)
	b.WriteString("persistent_keepalive_interval=25\n")
	return b.String()
}

// Start 建立底層 WireGuard 裝置並啟動（不等待握手完成）。
func (w *wireTunnel) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dev != nil {
		return nil
	}
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

// DialContext 經隧道撥號（TCP）。
func (w *wireTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	w.mu.Lock()
	tnet := w.net
	w.mu.Unlock()
	if tnet == nil {
		return nil, fmt.Errorf("隧道 %s 未運行", w.id)
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return tnet.DialContext(ctx, "tcp", addr)
	default:
		return nil, fmt.Errorf("隧道 %s 不支援的網絡類型 %q", w.id, network)
	}
}
