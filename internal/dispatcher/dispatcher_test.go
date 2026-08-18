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
func (r *stubRegistry) Healthy() []tunnel.Tunnel { return r.healthy }
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
