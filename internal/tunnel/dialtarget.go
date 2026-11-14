package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// resolveTarget 把撥號目標轉為候選 AddrPort 清單（依序嘗試，保留故障轉移）。
// IP 字面值直連（不觸發解析）；域名經 cache（TTL 內免 DNS 往返）。
func resolveTarget(ctx context.Context, cache *dnsCache, addr string) ([]netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("目標地址 %q 無效: %w", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("目標端口無效 %q", addr)
	}

	if looksLikeIP(host) {
		if ip, perr := netip.ParseAddr(host); perr == nil {
			return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), uint16(port))}, nil
		}
	}

	if cache == nil {
		return nil, fmt.Errorf("目標 %q 是域名但無 DNS 快取可用", addr)
	}
	ips, rerr := cache.resolveHost(ctx, host)
	if rerr != nil {
		return nil, fmt.Errorf("解析 %s 失敗: %w", host, rerr)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("解析 %s 無可用位址", host)
	}
	// 位址在入快取時已解析；此處僅附上目標端口。
	out := make([]netip.AddrPort, len(ips))
	for i, ip := range ips {
		out[i] = netip.AddrPortFrom(ip, uint16(port))
	}
	return out, nil
}

// looksLikeIP 以首字元粗篩 IP 字面值：域名目標若直接丟給 ParseAddr，
// 失敗路徑會配置一個錯誤物件，而撥號熱路徑大多是域名。
func looksLikeIP(host string) bool {
	if host == "" {
		return false
	}
	c := host[0]
	return c == ':' || c >= '0' && c <= '9' || strings.IndexByte(host, ':') >= 0
}
