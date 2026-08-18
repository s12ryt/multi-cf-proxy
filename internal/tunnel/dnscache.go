package tunnel

import (
	"context"
	"errors"
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
// 負結果（錯誤）不快取。
type dnsCache struct {
	ttl     time.Duration // 0 = 停用（每次都解析）
	max     int           // 容量上限（逐出最舊）
	resolve func(ctx context.Context, host string) ([]string, error)
	now     func() time.Time // 可注入時鐘（測試）

	mu      sync.Mutex
	entries map[string]dnsEntry
	order   []string // 插入順序，容量逐出用
}

type dnsEntry struct {
	ips       []string
	expireAt  time.Time
	insertSeq int
}

// newDNSCache 建立快取。ttl 為 0 時停用；max 為容量上限。
func newDNSCache(ttl time.Duration, max int, resolve func(ctx context.Context, host string) ([]string, error)) *dnsCache {
	if max <= 0 {
		max = 256
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

// resolveHost 返回 host 的解析結果：TTL 內命中快取，否則經 resolve 解析並入快取。
func (c *dnsCache) resolveHost(ctx context.Context, host string) ([]string, error) {
	if c.ttl <= 0 { // 停用：永遠直解析
		return c.resolve(ctx, host)
	}
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[host]; ok && now.Before(e.expireAt) {
		c.mu.Unlock()
		return e.ips, nil
	}
	c.mu.Unlock()

	ips, err := c.resolve(ctx, host) // 解析在鎖外（可能阻塞數秒）
	if err != nil || len(ips) == 0 {
		if err == nil {
			err = errEmptyDNS
		}
		return nil, err // 負結果不快取
	}

	c.mu.Lock()
	c.evictLocked()
	c.entries[host] = dnsEntry{ips: ips, expireAt: now.Add(c.ttl)}
	if !containsStr(c.order, host) {
		c.order = append(c.order, host)
	}
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

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
