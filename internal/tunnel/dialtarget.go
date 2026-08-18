package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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

	if ip, perr := netip.ParseAddr(host); perr == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), uint16(port))}, nil
	}

	if cache == nil {
		return nil, fmt.Errorf("目標 %q 是域名但無 DNS 快取可用", addr)
	}
	ips, rerr := cache.resolveHost(ctx, host)
	if rerr != nil {
		return nil, fmt.Errorf("解析 %s 失敗: %w", host, rerr)
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, s := range ips {
		ip, perr := netip.ParseAddr(s)
		if perr != nil {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip.Unmap(), uint16(port)))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("解析 %s 無可用位址", host)
	}
	return out, nil
}
