package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// errEmptyDNS 解析成功但無結果時的語意錯誤。
var errEmptyDNS = errors.New("域名解析無結果")

// dnsCacheMaxEntries 每條隧道的快取容量上限。
const dnsCacheMaxEntries = 256

// dnsCache 以固定 TTL 快取「經隧道解析」的域名結果，消除同域名重複連線的
// 額外 DNS 往返（wireguard-go tun/netstack 的 DialContext 每次都會解析）。
// 每條隧道各持一份實例：解析發生在本隧道內，避免跨出口污染。
// 負結果（錯誤）不快取。存的是已解析的 netip.Addr——撥號路徑每條連線都要用，
// 快取字串會讓每次命中重跑一輪位址解析。
type dnsCache struct {
	max     int // 容量上限（逐出最舊）
	resolve func(ctx context.Context, host string) ([]string, error)
	now     func() time.Time // 可注入時鐘（測試）

	mu      sync.Mutex
	ttl     time.Duration // 0 = 停用（每次都解析）；與 setTTL 併發，須持鎖讀
	entries map[string]dnsEntry
	order   []string // 插入順序，容量逐出用
}

type dnsEntry struct {
	ips      []netip.Addr
	expireAt time.Time
}

// newDNSCache 建立快取。ttl 為 0 時停用；max 為容量上限。
func newDNSCache(ttl time.Duration, max int, resolve func(ctx context.Context, host string) ([]string, error)) *dnsCache {
	if max <= 0 {
		max = dnsCacheMaxEntries
	}
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]string, error) {
			return nil, nil
		}
	}
	return &dnsCache{
		ttl:     ttl,
		max:     max,
		resolve: resolve,
		now:     time.Now,
		entries: map[string]dnsEntry{},
	}
}

// setTTL 更新 TTL（運行時調整用；0 = 停用快取）。
func (c *dnsCache) setTTL(d time.Duration) {
	c.mu.Lock()
	c.ttl = d
	c.mu.Unlock()
}

// resolveHost 返回 host 的解析位址：TTL 內命中快取，否則經 resolve 解析並入快取。
func (c *dnsCache) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	now := c.now()
	c.mu.Lock()
	ttl := c.ttl
	if ttl > 0 {
		if e, ok := c.entries[host]; ok && now.Before(e.expireAt) {
			c.mu.Unlock()
			return e.ips, nil
		}
	}
	c.mu.Unlock()

	raw, err := c.resolve(ctx, host) // 解析在鎖外（可能阻塞數秒）
	if err == nil && len(raw) == 0 {
		err = errEmptyDNS
	}
	if err != nil {
		return nil, err // 負結果不快取
	}
	ips := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		if ip, perr := netip.ParseAddr(s); perr == nil {
			ips = append(ips, ip.Unmap())
		}
	}
	if len(ips) == 0 {
		return nil, errEmptyDNS
	}
	if ttl <= 0 { // 停用快取：直接交付，不入表
		return ips, nil
	}

	c.mu.Lock()
	if _, exists := c.entries[host]; !exists {
		c.evictLocked()
		c.order = append(c.order, host) // 僅新鍵入順序表；刷新不膨脹、無需線性掃描
	}
	c.entries[host] = dnsEntry{ips: ips, expireAt: now.Add(ttl)}
	c.mu.Unlock()
	return ips, nil
}

// evictLocked 容量滿時逐出最舊條目（呼叫方持鎖）。
func (c *dnsCache) evictLocked() {
	for len(c.order) >= c.max {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}
