package dispatcher

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/stats"
	"multi-cf-proxy/internal/tunnel"
)

// stubTunnel 腳本化隧道。
type stubTunnel struct {
	id      string
	dialErr atomic.Value // error
	dials   atomic.Int64
}

func (s *stubTunnel) ID() string { return s.id }
func (s *stubTunnel) Fingerprint() string {
	return ""
}
func (s *stubTunnel) Start(ctx context.Context) error   { return nil }
func (s *stubTunnel) Stop()                             {}
func (s *stubTunnel) Rebuild(ctx context.Context) error { return nil }
func (s *stubTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	s.dials.Add(1)
	if e, ok := s.dialErr.Load().(error); ok && e != nil {
		return nil, e
	}
	c1, c2 := net.Pipe()
	go io.Copy(io.Discard, c2) // 模擬遠端
	return c1, nil
}

// stubRegistry 腳本化註冊表。
type stubRegistry struct {
	bound   map[string]tunnel.Tunnel
	healthy []tunnel.Tunnel
	health  map[string]bool
}

func (r *stubRegistry) Bound(id string) (tunnel.Tunnel, bool) {
	t, ok := r.bound[id]
	return t, ok
}
func (r *stubRegistry) Healthy() []tunnel.Tunnel                  { return r.healthy }
func (r *stubRegistry) HealthySortedByLatency() []tunnel.Tunnel   { return r.healthy }
func (r *stubRegistry) LatencyOf(id string) (time.Duration, bool) { return 0, false }
func (r *stubRegistry) IsHealthy(id string) bool {
	return r.health[id]
}

func mkService(t *testing.T, reg Registry) *Service {
	t.Helper()
	up1 := &config.Upstream{ID: "u1", Enabled: true, Account: config.Account{Username: "warp-aaaa", Password: "pw1"}}
	up2 := &config.Upstream{ID: "u2", Enabled: true, Account: config.Account{Username: "warp-bbbb", Password: "pw2"}}
	return NewService(auth.NewStore([]*config.Upstream{up1, up2}), reg, stats.NewCollector())
}

func TestRouteAuthFail(t *testing.T) {
	reg := &stubRegistry{health: map[string]bool{}}
	s := mkService(t, reg)
	_, _, err := s.Route(context.Background(), "warp-aaaa", "wrong", "tcp", "example.com:443")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("錯誤密碼應返回 ErrAuth, got %v", err)
	}
	_, _, err = s.Route(context.Background(), "unknown", "pw", "tcp", "example.com:443")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("未知用戶應返回 ErrAuth, got %v", err)
	}
}

func TestRouteBoundHealthy(t *testing.T) {
	u1 := &stubTunnel{id: "u1"}
	u2 := &stubTunnel{id: "u2"}
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": u1, "u2": u2},
		healthy: []tunnel.Tunnel{u1, u2},
		health:  map[string]bool{"u1": true, "u2": true},
	}
	s := mkService(t, reg)

	conn, used, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if used != "u1" {
		t.Errorf("應使用綁定上游 u1, got %s", used)
	}
	if u1.dials.Load() != 1 || u2.dials.Load() != 0 {
		t.Errorf("健康綁定上游應直接使用: u1=%d u2=%d", u1.dials.Load(), u2.dials.Load())
	}
}

func TestRouteFailoverWhenBoundDialFails(t *testing.T) {
	u1 := &stubTunnel{id: "u1"}
	u1.dialErr.Store(errors.New("tunnel broken"))
	u2 := &stubTunnel{id: "u2"}
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": u1, "u2": u2},
		healthy: []tunnel.Tunnel{u1, u2},
		health:  map[string]bool{"u1": true, "u2": true},
	}
	s := mkService(t, reg)

	conn, used, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("綁定上游撥號失敗應 failover: %v", err)
	}
	defer conn.Close()
	if used != "u2" {
		t.Errorf("應切換到 u2, got %s", used)
	}
}

func TestRouteSkipUnhealthyBound(t *testing.T) {
	u1 := &stubTunnel{id: "u1"}
	u2 := &stubTunnel{id: "u2"}
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": u1, "u2": u2},
		healthy: []tunnel.Tunnel{u2},
		health:  map[string]bool{"u1": false, "u2": true},
	}
	s := mkService(t, reg)

	conn, used, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if used != "u2" {
		t.Errorf("不健康綁定上游應跳過, got %s", used)
	}
	if u1.dials.Load() != 0 {
		t.Error("不應嘗試不健康的綁定上游")
	}
}

func TestRouteNoHealthyUpstream(t *testing.T) {
	u1 := &stubTunnel{id: "u1"}
	reg := &stubRegistry{
		bound:  map[string]tunnel.Tunnel{"u1": u1},
		health: map[string]bool{"u1": false},
	}
	s := mkService(t, reg)

	_, _, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if !errors.Is(err, ErrNoHealthyUpstream) {
		t.Fatalf("無健康上游應返回 ErrNoHealthyUpstream, got %v", err)
	}
}

func TestRouteAllFail(t *testing.T) {
	u1 := &stubTunnel{id: "u1"}
	u1.dialErr.Store(errors.New("e1"))
	u2 := &stubTunnel{id: "u2"}
	u2.dialErr.Store(errors.New("e2"))
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": u1, "u2": u2},
		healthy: []tunnel.Tunnel{u1, u2},
		health:  map[string]bool{"u1": true, "u2": true},
	}
	s := mkService(t, reg)

	_, _, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err == nil {
		t.Fatal("全部失敗應報錯")
	}
	if u1.dials.Load() == 0 || u2.dials.Load() == 0 {
		t.Error("應逐一嘗試所有候選上游")
	}
}

func TestRouteStatsAttribution(t *testing.T) {
	u2 := &stubTunnel{id: "u2"}
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u2": u2},
		healthy: []tunnel.Tunnel{u2},
		health:  map[string]bool{"u2": true},
	}
	col := stats.NewCollector()
	up1 := &config.Upstream{ID: "u1", Enabled: true, Account: config.Account{Username: "warp-aaaa", Password: "pw1"}}
	s := NewService(auth.NewStore([]*config.Upstream{up1}), reg, col)

	conn, used, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "1.2.3.4:443")
	if err != nil || used != "u2" {
		t.Fatalf("route: %v %s", err, used)
	}
	n, _ := conn.Write([]byte("hello"))
	if n != 5 {
		t.Fatal("write 失敗")
	}
	conn.Close()

	snap := col.Snapshot()
	if snap.Accounts["warp-aaaa"].UpBytes != 5 {
		t.Errorf("帳號統計 = %+v", snap.Accounts["warp-aaaa"])
	}
	if snap.Upstreams["u2"].UpBytes != 5 {
		t.Errorf("實際出口 u2 統計 = %+v", snap.Upstreams["u2"])
	}
}

func TestRouteDialTimeout(t *testing.T) {
	u1 := &stubTunnel{id: "u1"}
	u1.dialErr.Store(context.DeadlineExceeded)
	u2 := &stubTunnel{id: "u2"}
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": u1, "u2": u2},
		healthy: []tunnel.Tunnel{u1, u2},
		health:  map[string]bool{"u1": true, "u2": true},
	}
	s := mkService(t, reg)
	s.dialTimeout = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, used, err := s.Route(ctx, "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("超時的上游應被跳過: %v", err)
	}
	defer conn.Close()
	if used != "u2" {
		t.Errorf("應切換到 u2, got %s", used)
	}
}

// TestRouteRecordsDialLatency Route 成功後應記錄一筆撥號延遲樣本。
func TestRouteRecordsDialLatency(t *testing.T) {
	up1 := &config.Upstream{ID: "u1", Enabled: true, Account: config.Account{Username: "warp-aaaa", Password: "pw1"}}
	col := stats.NewCollector()
	tun := &stubTunnel{id: "u1"}
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": tun},
		healthy: []tunnel.Tunnel{tun},
		health:  map[string]bool{"u1": true},
	}
	s := NewService(auth.NewStore([]*config.Upstream{up1}), reg, col)

	conn, _, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Route 失敗: %v", err)
	}
	conn.Close()
	d := col.Snapshot().Dial
	if d.Count != 1 {
		t.Fatalf("Dial.Count = %d, want 1（成功撥號應被記錄）", d.Count)
	}
	if d.MaxMS < 0 {
		t.Errorf("耗時不應為負: %+v", d)
	}
}

// TestRouteDialFailNoSample 撥號失敗不記錄延遲樣本（避免污染成功延遲分佈）。
func TestRouteDialFailNoSample(t *testing.T) {
	up1 := &config.Upstream{ID: "u1", Enabled: true, Account: config.Account{Username: "warp-aaaa", Password: "pw1"}}
	col := stats.NewCollector()
	tun := &stubTunnel{id: "u1"}
	tun.dialErr.Store(errors.New("dial fail"))
	reg := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": tun},
		healthy: []tunnel.Tunnel{tun},
		health:  map[string]bool{"u1": true},
	}
	s := NewService(auth.NewStore([]*config.Upstream{up1}), reg, col)

	_, _, err := s.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err == nil {
		t.Fatal("應失敗")
	}
	if d := col.Snapshot().Dial; d.Count != 0 {
		t.Errorf("失敗撥號不應記錄樣本, got Count=%d", d.Count)
	}
}

// --- v1.6.5：延遲優選路由（備援排序 + 全域優先 + 黏住/容差） ---

// latRegistry 在 stubRegistry 上附加延遲資訊（HealthySortedByLatency 由測試排列）。
type latRegistry struct {
	stubRegistry
	sorted    []tunnel.Tunnel
	latencies map[string]time.Duration
}

func (r *latRegistry) HealthySortedByLatency() []tunnel.Tunnel { return r.sorted }
func (r *latRegistry) LatencyOf(id string) (time.Duration, bool) {
	d, ok := r.latencies[id]
	return d, ok
}

func newLatService(t *testing.T) (*Service, *latRegistry) {
	t.Helper()
	u1 := &stubTunnel{id: "u1"}
	u2 := &stubTunnel{id: "u2"}
	reg := &latRegistry{
		stubRegistry: stubRegistry{
			bound:   map[string]tunnel.Tunnel{"u1": u1, "u2": u2},
			healthy: []tunnel.Tunnel{u1, u2},
			health:  map[string]bool{"u1": true, "u2": true},
		},
		sorted:    []tunnel.Tunnel{u2, u1},
		latencies: map[string]time.Duration{"u1": 100 * time.Millisecond, "u2": 50 * time.Millisecond},
	}
	return mkService(t, reg), reg
}

// TestFallbackSortedByLatency 綁定不健康需 failover 時，備援按延遲排序（非配置順序）。
func TestFallbackSortedByLatency(t *testing.T) {
	svc, reg := newLatService(t)
	reg.health["u1"] = false
	reg.healthy = []tunnel.Tunnel{reg.bound["u2"]}
	reg.sorted = []tunnel.Tunnel{reg.bound["u2"]}

	// 帳號 warp-aaaa 綁 u1（不健康）→ 備援只有 u2
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u2" {
		t.Errorf("應 failover 到 u2, got %s", used)
	}

	// 綁定 u1 仍不健康；新增更快的 u3（30ms）→ 備援按延遲先試 u3（非配置順序 u2）
	u3 := &stubTunnel{id: "u3"}
	reg.bound["u3"] = u3
	reg.health["u3"] = true
	reg.latencies["u3"] = 30 * time.Millisecond
	reg.healthy = []tunnel.Tunnel{reg.bound["u2"], u3} // 配置順序：u2 在前
	reg.sorted = []tunnel.Tunnel{u3, reg.bound["u2"]}  // 延遲排序：u3 在前
	conn, used, err = svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u3" {
		t.Errorf("備援應按延遲排序先試 u3（更快）, got %s", used)
	}

	// 綁定 u1 恢復健康 → 回到綁定優先（不因延遲排序動搖）
	reg.health["u1"] = true
	reg.healthy = []tunnel.Tunnel{reg.bound["u1"], reg.bound["u2"], u3}
	conn, used, err = svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u1" {
		t.Errorf("綁定上游恢復健康應回到綁定 u1, got %s", used)
	}
}

// TestGlobalPreferInitialFastest 全域模式：初始目標＝當前最快（不論綁定）。
func TestGlobalPreferInitialFastest(t *testing.T) {
	svc, _ := newLatService(t)
	svc.SetLatencyRouting(true, 20*time.Millisecond)

	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u2" {
		t.Errorf("全域模式初始應走最快 u2（warp-aaaa 原綁 u1）, got %s", used)
	}
}

// TestGlobalStickyWithinMargin 容差內黏住：快不到容差（5ms < 20ms）不切換。
func TestGlobalStickyWithinMargin(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 20*time.Millisecond)

	conn, _, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// u1 提速到 45ms（比黏住的 u2=50ms 快 5ms，未超容差）→ 仍走 u2
	reg.latencies["u1"] = 45 * time.Millisecond
	reg.sorted = []tunnel.Tunnel{reg.bound["u1"], reg.bound["u2"]}
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u2" {
		t.Errorf("容差內應黏住 u2, got %s", used)
	}
}

// TestGlobalDriftBeyondMargin 超過容差（40ms > 20ms）漂移到更快上游。
func TestGlobalDriftBeyondMargin(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 20*time.Millisecond)

	conn, _, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	reg.latencies["u1"] = 10 * time.Millisecond
	reg.sorted = []tunnel.Tunnel{reg.bound["u1"], reg.bound["u2"]}
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u1" {
		t.Errorf("超容差應漂移到 u1, got %s", used)
	}
}

// TestGlobalStickyUnhealthySwitch 黏住上游不健康時立即改選最快（不受容差限制）。
func TestGlobalStickyUnhealthySwitch(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 20*time.Millisecond)

	conn, _, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	reg.health["u2"] = false
	reg.healthy = []tunnel.Tunnel{reg.bound["u1"]}
	reg.sorted = []tunnel.Tunnel{reg.bound["u1"]}
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u1" {
		t.Errorf("黏住上游不健康應立即切最快 u1, got %s", used)
	}
}

// TestGlobalMarginZeroAlwaysSwitch margin=0 停用防抖：任何更快即切。
func TestGlobalMarginZeroAlwaysSwitch(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 0)

	conn, _, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	reg.latencies["u1"] = 49 * time.Millisecond // 僅快 1ms
	reg.sorted = []tunnel.Tunnel{reg.bound["u1"], reg.bound["u2"]}
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u1" {
		t.Errorf("margin=0 時任何更快都應切換, got %s", used)
	}
}

// TestGlobalDialFailFallsToNext 黏住目標撥號失敗時按延遲序落到下一個。
func TestGlobalDialFailFallsToNext(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 20*time.Millisecond)

	conn, _, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	reg.bound["u2"].(*stubTunnel).dialErr.Store(errors.New("broken"))
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u1" {
		t.Errorf("黏住上游撥號失敗應落到 u1, got %s", used)
	}
}

// TestSetLatencyRoutingToggleOff 關閉全域模式回到綁定行為。
func TestSetLatencyRoutingToggleOff(t *testing.T) {
	svc, _ := newLatService(t)
	svc.SetLatencyRouting(true, 20*time.Millisecond)
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil || used != "u2" {
		t.Fatalf("前置：全域模式應走 u2, got %s (%v)", used, err)
	}
	conn.Close()

	svc.SetLatencyRouting(false, 20*time.Millisecond)
	conn, used, err = svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if used != "u1" {
		t.Errorf("關閉全域模式應回到綁定 u1, got %s", used)
	}
}

func TestEgressSnapshot(t *testing.T) {
	svc, _ := newLatService(t)

	// 非全域模式：快照為空
	if got := svc.EgressSnapshot(); len(got) != 0 {
		t.Errorf("非全域模式快照應為空, got %v", got)
	}

	// 開啟全域：u2(50ms) 最快 → 帳號走 u2
	svc.SetLatencyRouting(true, 20*time.Millisecond)
	conn, used, err := svc.Route(context.Background(), "warp-aaaa", "pw1", "tcp", "example.com:443")
	if err != nil || used != "u2" {
		t.Fatalf("Route = %s, %v", used, err)
	}
	conn.Close()
	snap := svc.EgressSnapshot()
	if snap["warp-aaaa"] != "u2" {
		t.Errorf("快照應記錄實際出口 u2, got %v", snap)
	}

	// 關閉全域：快照清空
	svc.SetLatencyRouting(false, 0)
	if got := svc.EgressSnapshot(); len(got) != 0 {
		t.Errorf("關閉後快照應清空, got %v", got)
	}
}
