// Package stats 提供併發安全的流量統計（每帳號/每上游，IPv4/IPv6 分開）。
package stats

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamStats 單個上游的累計流量（位元組）。
type UpstreamStats struct {
	UpBytes       int64 `json:"up_bytes"`
	DownBytes     int64 `json:"down_bytes"`
	IPv6UpBytes   int64 `json:"ipv6_up_bytes"`
	IPv6DownBytes int64 `json:"ipv6_down_bytes"`
}

// AccountStats 單個入站帳號的累計流量與連接情況。
type AccountStats struct {
	UpBytes     int64     `json:"up_bytes"`
	DownBytes   int64     `json:"down_bytes"`
	Connections int64     `json:"connections"` // 當前活躍
	TotalConns  int64     `json:"total_conns"` // 歷史累計
	LastActive  time.Time `json:"last_active"`
}

// Snapshot 統計快照。
type Snapshot struct {
	Upstreams map[string]UpstreamStats `json:"upstreams"`
	Accounts  map[string]AccountStats  `json:"accounts"`
}

type counters struct {
	up, down           atomic.Int64
	up6, down6         atomic.Int64
	conns, totalConns  atomic.Int64
	lastActiveUnixNano atomic.Int64
}

// Collector 收集器。零值可用。
type Collector struct {
	mu        sync.Mutex // 保護兩個 map 的建立與替換
	upstreams map[string]*counters
	accounts  map[string]*counters
}

// NewCollector 建立收集器。
func NewCollector() *Collector {
	return &Collector{
		upstreams: map[string]*counters{},
		accounts:  map[string]*counters{},
	}
}

func (c *Collector) upEntry(key string) *counters {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.upstreams[key]
	if !ok {
		e = &counters{}
		c.upstreams[key] = e
	}
	return e
}

func (c *Collector) accountEntry(key string) *counters {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.accounts[key]
	if !ok {
		e = &counters{}
		c.accounts[key] = e
	}
	return e
}

// AccountUp 記錄帳號上行位元組數。
func (c *Collector) AccountUp(name string, n int) {
	e := c.accountEntry(name)
	e.up.Add(int64(n))
	e.lastActiveUnixNano.Store(time.Now().UnixNano())
}

// AccountDown 記錄帳號下行位元組數。
func (c *Collector) AccountDown(name string, n int) {
	e := c.accountEntry(name)
	e.down.Add(int64(n))
	e.lastActiveUnixNano.Store(time.Now().UnixNano())
}

// ConnOpen 帳號開啟一條連接。
func (c *Collector) ConnOpen(name string) {
	e := c.accountEntry(name)
	e.conns.Add(1)
	e.totalConns.Add(1)
	e.lastActiveUnixNano.Store(time.Now().UnixNano())
}

// ConnClose 帳號關閉一條連接。
func (c *Collector) ConnClose(name string) {
	e := c.accountEntry(name)
	e.conns.Add(-1)
	e.lastActiveUnixNano.Store(time.Now().UnixNano())
}

// Snapshot 取當前統計快照。
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	ups := make(map[string]UpstreamStats, len(c.upstreams))
	for id, e := range c.upstreams {
		ups[id] = UpstreamStats{
			UpBytes:       e.up.Load(),
			DownBytes:     e.down.Load(),
			IPv6UpBytes:   e.up6.Load(),
			IPv6DownBytes: e.down6.Load(),
		}
	}
	accs := make(map[string]AccountStats, len(c.accounts))
	for name, e := range c.accounts {
		accs[name] = AccountStats{
			UpBytes:     e.up.Load(),
			DownBytes:   e.down.Load(),
			Connections: e.conns.Load(),
			TotalConns:  e.totalConns.Load(),
			LastActive:  time.Unix(0, e.lastActiveUnixNano.Load()),
		}
	}
	c.mu.Unlock()
	return Snapshot{Upstreams: ups, Accounts: accs}
}

type accKind int

const (
	kindUp accKind = iota
	kindDown
)

// wrapErrCounting 已統計位元組數的連線包裝器。
type countingConn struct {
	net.Conn
	collector *Collector
	account   string
	acc       func(kind accKind, n int)
	closed    bool
	once      sync.Once
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.acc(kindDown, n) // 對客戶端而言，從上游讀 = 下行
		c.collector.AccountDown(c.account, n)
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.acc(kindUp, n)
		c.collector.AccountUp(c.account, n)
	}
	return n, err
}

func (c *countingConn) Close() error {
	c.once.Do(func() {
		c.closed = true
		c.collector.ConnClose(c.account)
	})
	return c.Conn.Close()
}

func isIPv6(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// WrapConn 包裝一條已建立的出站連線：自動按 IP 族群與方向統計流量。
// 上游統計在 Wrap 時確定 v4/v6 歸屬（連線的遠端位址族群）。
func (c *Collector) WrapConn(conn net.Conn, upstreamID, account string) net.Conn {
	v6 := isIPv6(conn.RemoteAddr().String())
	e := c.upEntry(upstreamID)
	acc := func(kind accKind, n int) {
		if v6 {
			if kind == kindUp {
				e.up6.Add(int64(n))
			} else {
				e.down6.Add(int64(n))
			}
		} else {
			if kind == kindUp {
				e.up.Add(int64(n))
			} else {
				e.down.Add(int64(n))
			}
		}
	}
	c.ConnOpen(account)
	return &countingConn{Conn: conn, collector: c, account: account, acc: acc}
}
