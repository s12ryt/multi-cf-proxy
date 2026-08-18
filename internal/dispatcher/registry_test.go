package dispatcher

import (
	"context"
	"net"
	"testing"
	"time"

	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/tunnel"
)

func TestTunnelManagerRegistry(t *testing.T) {
	ups := []*config.Upstream{
		{ID: "u1", Enabled: true, PrivateKey: "a", PeerPublicKey: "p", Endpoint: "e:1", Addresses: []string{"172.16.0.2/32"}},
		{ID: "u2", Enabled: true, PrivateKey: "b", PeerPublicKey: "p", Endpoint: "e:1", Addresses: []string{"172.16.0.3/32"}},
	}
	tm := tunnel.NewManager(func(u *config.Upstream) (tunnel.Tunnel, error) {
		return &noopTunnel{id: u.ID}, nil
	}, tunnel.DefaultProbe, time.Second, 1)
	if err := tm.Sync(t.Context(), ups); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry(tm)
	if tn, ok := reg.Bound("u1"); !ok || tn.ID() != "u1" {
		t.Errorf("Bound(u1) = %v, %v", tn, ok)
	}
	if _, ok := reg.Bound("nope"); ok {
		t.Error("不存在的上游應返回 false")
	}
	if len(reg.Healthy()) != 2 {
		t.Errorf("Healthy() = %d", len(reg.Healthy()))
	}
	if !reg.IsHealthy("u1") {
		t.Error("u1 初始應樂觀健康")
	}

	// u2 失敗一次（閾值 1）→ 不健康
	tm.RecordProbe("u2", errProbe, 0)
	if reg.IsHealthy("u2") {
		t.Error("u2 應不健康")
	}
	if len(reg.Healthy()) != 1 {
		t.Errorf("Healthy() = %d", len(reg.Healthy()))
	}
}

type noopTunnel struct{ id string }

func (n *noopTunnel) ID() string                        { return n.id }
func (n *noopTunnel) Fingerprint() string               { return "" }
func (n *noopTunnel) Start(ctx context.Context) error   { return nil }
func (n *noopTunnel) Stop()                             {}
func (n *noopTunnel) Rebuild(ctx context.Context) error { return nil }
func (n *noopTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errProbe
}
