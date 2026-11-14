// Package stats 提供併發安全的流量統計（每帳號/每上游，IPv4/IPv6 分開）。
package stats

import (
	"net"
	"slices"
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

// DialStats 撥號延遲分佈快照（最近樣本的 nearest-rank 百分位，毫秒）。
type DialStats struct {
	Count int64 `json:"count"`
	P50MS int64 `json:"p50_ms"`
	P95MS int64 `json:"p95_ms"`
	MaxMS int64 `json:"max_ms"`
}

// Snapshot 統計快照。
type Snapshot struct {
	Upstreams map[string]UpstreamStats `json:"upstreams"`
	Accounts  map[string]AccountStats  `json:"accounts"`
	Dial      DialStats                `json:"dial"`
}

type counters struct {
	up, down           atomic.Int64
	up6, down6         atomic.Int64
	conns, totalConns  atomic.Int64
	lastActiveUnixNano atomic.Int64
}

// touch 標記最近活躍時刻。
func (e *counters) touch() {
	e.lastActiveUnixNano.Store(time.Now().UnixNano())
}

// Collector 收集器。零值可用。
type Collector struct {
	mu        sync.Mutex // 保護兩個 map 的建立與替換
	upstreams map[string]*counters
	accounts  map[string]*counters

	dialMu      sync.Mutex // 保護撥號延遲環形緩衝
	dialSamples []int64    // 毫秒樣本（環形，容量 dialSampleCap）
	dialPos     int        // 環形寫入位置（僅在滿環後使用）
}

// dialSampleCap 撥號延遲樣本環形容量：保留最近 512 筆，足以反映近期趨勢。
const dialSampleCap = 512

// NewCollector 建立收集器。
func NewCollector() *Collector {
	return &Collector{
		upstreams: map[string]*counters{},
		accounts:  map[string]*counters{},
	}
}

// RecordDial 記錄一筆成功撥號的耗時（只統計成功路徑，避免失敗污染分佈）。
func (c *Collector) RecordDial(d time.Duration) {
	ms := d.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	if c.dialSamples == nil {
		c.dialSamples = make([]int64, 0, dialSampleCap)
	}
	if len(c.dialSamples) < dialSampleCap {
		c.dialSamples = append(c.dialSamples, ms)
		return
	}
	c.dialSamples[c.dialPos] = ms
	c.dialPos = (c.dialPos + 1) % dialSampleCap
}

// dialPercentiles 就地樣本計算 nearest-rank 百分位（rank = ceil(p/100·n)，1-based）。
func dialPercentiles(samples []int64) DialStats {
	n := len(samples)
	if n == 0 {
		return DialStats{}
	}
	sorted := make([]int64, n)
	copy(sorted, samples)
	slices.Sort(sorted) // 泛型排序：免反射與比較閉包
	rank := func(p int) int64 {
		r := (p*n + 99) / 100 // ceil(p*n/100)
		if r < 1 {
			r = 1
		}
		return sorted[r-1]
	}
	return DialStats{
		Count: int64(n),
		P50MS: rank(50),
		P95MS: rank(95),
		MaxMS: sorted[n-1],
	}
}

// entry 取得（或建立）映射中的計數器；呼叫方須持 c.mu。
func entry(m map[string]*counters, key string) *counters {
	e, ok := m[key]
	if !ok {
		e = &counters{}
		m[key] = e
	}
	return e
}

func (c *Collector) accountEntry(key string) *counters {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accounts == nil {
		c.accounts = map[string]*counters{}
	}
	return entry(c.accounts, key)
}

// pairEntries 一次取鎖取得上游與帳號計數器（連線建立路徑原本要取三次鎖）。
func (c *Collector) pairEntries(upstreamID, account string) (*counters, *counters) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.upstreams == nil {
		c.upstreams = map[string]*counters{}
	}
	if c.accounts == nil {
		c.accounts = map[string]*counters{}
	}
	return entry(c.upstreams, upstreamID), entry(c.accounts, account)
}

// AccountUp 記錄帳號上行位元組數。
func (c *Collector) AccountUp(name string, n int) {
	e := c.accountEntry(name)
	e.up.Add(int64(n))
	e.touch()
}

// AccountDown 記錄帳號下行位元組數。
func (c *Collector) AccountDown(name string, n int) {
	e := c.accountEntry(name)
	e.down.Add(int64(n))
	e.touch()
}

// ConnOpen 帳號開啟一條連接。
func (c *Collector) ConnOpen(name string) {
	connOpen(c.accountEntry(name))
}

// ConnClose 帳號關閉一條連接。
func (c *Collector) ConnClose(name string) {
	connClose(c.accountEntry(name))
}

func connOpen(e *counters) {
	e.conns.Add(1)
	e.totalConns.Add(1)
	e.touch()
}

func connClose(e *counters) {
	e.conns.Add(-1)
	e.touch()
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
	c.dialMu.Lock()
	dial := dialPercentiles(c.dialSamples)
	c.dialMu.Unlock()
	return Snapshot{Upstreams: ups, Accounts: accs, Dial: dial}
}

// countingConn 計量連線：計數器在包裝時解析完成，
// 每個封包只做原子加法——不查映射、不取鎖、不配置、無閉包間接呼叫。
type countingConn struct {
	net.Conn
	up, down *atomic.Int64 // 上游方向計數（已按 IP 族群選定）
	acct     *counters     // 帳號計數
	closed   atomic.Bool
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.down.Add(int64(n)) // 對客戶端而言，從上游讀 = 下行
		c.acct.down.Add(int64(n))
		c.acct.touch()
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.up.Add(int64(n))
		c.acct.up.Add(int64(n))
		c.acct.touch()
	}
	return n, err
}

func (c *countingConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		connClose(c.acct)
	}
	return c.Conn.Close()
}

// isIPv6Addr 判斷遠端位址是否為 IPv6；優先走結構化位址，
// 避免 String() 格式化與再解析（每條連線一次字串配置）。
func isIPv6Addr(addr net.Addr) bool {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP != nil && a.IP.To4() == nil
	case *net.UDPAddr:
		return a.IP != nil && a.IP.To4() == nil
	}
	s := addr.String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

// WrapConn 包裝一條已建立的出站連線：自動按 IP 族群與方向統計流量。
// 上游統計在 Wrap 時確定 v4/v6 歸屬（連線的遠端位址族群）。
func (c *Collector) WrapConn(conn net.Conn, upstreamID, account string) net.Conn {
	ue, ae := c.pairEntries(upstreamID, account)
	connOpen(ae)
	cc := &countingConn{Conn: conn, acct: ae}
	if isIPv6Addr(conn.RemoteAddr()) {
		cc.up, cc.down = &ue.up6, &ue.down6
	} else {
		cc.up, cc.down = &ue.up, &ue.down
	}
	return cc
}
