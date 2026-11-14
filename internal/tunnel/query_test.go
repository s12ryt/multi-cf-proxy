// 覆蓋 A64：Manager 的零配置狀態查詢（Latency / IsHealthy）。
// 選路熱路徑每條連線呼多次，不得經 States() 全量複製。
package tunnel

import (
	"context"
	"testing"
	"time"

	"multi-cf-proxy/internal/config"
)

// queryManager 建一個不自動巡檢的 Manager（interval 極大），含 u1 啟用、u2 停用。
func queryManager(t *testing.T) *Manager {
	t.Helper()
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 100)
	ups := []*config.Upstream{mkUpstream("u1", true), mkUpstream("u2", false)}
	if err := m.Sync(context.Background(), ups); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHealthyRankedCarriesEMA(t *testing.T) {
	m := queryManager(t)
	m.RecordLatency("u1", nil, 12*time.Millisecond)

	got := m.HealthyRanked()
	if len(got) != 1 || got[0].Tunnel.ID() != "u1" {
		t.Fatalf("僅 u1 運行中: %v", got)
	}
	if got[0].Latency != 12*time.Millisecond {
		t.Errorf("延遲應為首次原始值 12ms: %v", got[0].Latency)
	}
}

func TestManagerIsHealthy(t *testing.T) {
	m := queryManager(t)
	m.RecordProbe("u1", nil, 5*time.Millisecond)
	m.RecordProbe("u2", nil, 5*time.Millisecond)

	if !m.IsHealthy("u1") {
		t.Error("運行中且探測成功的上游應為健康")
	}
	if m.IsHealthy("u2") {
		t.Error("未運行的上游不應判健康")
	}
	if m.IsHealthy("none") {
		t.Error("不存在的上游不應判健康")
	}
}

// BenchmarkHealthyRanked / BenchmarkRankedPlusLookup 對照選路熱路徑的兩種取值方式：
// 後者為優化前的實際路徑（清單 + 逐個回查延遲，各自獨立取鎖）。
func BenchmarkHealthyRanked(b *testing.B) {
	m := queryManager(&testing.T{})
	m.RecordLatency("u1", nil, 9*time.Millisecond)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.HealthyRanked()
	}
}

func BenchmarkRankedPlusLookup(b *testing.B) {
	m := queryManager(&testing.T{})
	m.RecordLatency("u1", nil, 9*time.Millisecond)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, r := range m.HealthyRanked() {
			_ = m.States()[r.Tunnel.ID()].LastLatency
		}
	}
}

func BenchmarkIsHealthy(b *testing.B) {
	m := queryManager(&testing.T{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.IsHealthy("u1")
	}
}
