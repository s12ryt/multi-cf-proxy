// 覆蓋 A69：選路熱路徑的註冊表查詢次數上限（效能契約）。
// candidates 每條入站連線都走一次，重複的 O(N) 掃描會放大為 O(N^2) 查詢。
package dispatcher

import (
	"sync/atomic"
	"testing"
	"time"

	"multi-cf-proxy/internal/tunnel"
)

// countingRegistry 統計熱路徑上的註冊表查詢次數。
type countingRegistry struct {
	*stubRegistry
	rankCalls   atomic.Int64
	healthCalls atomic.Int64
}

func (r *countingRegistry) HealthyRanked() []tunnel.Ranked {
	r.rankCalls.Add(1)
	return r.stubRegistry.HealthyRanked()
}

func (r *countingRegistry) IsHealthy(id string) bool {
	r.healthCalls.Add(1)
	return r.stubRegistry.IsHealthy(id)
}

func (r *countingRegistry) reset() {
	r.rankCalls.Store(0)
	r.healthCalls.Store(0)
}

// countingService 三條健康隧道，延遲刻意讓前兩條未知：
// 迫使 driftTarget 掃到最後一條，暴露重複掃描。
func countingService(t *testing.T) (*Service, *countingRegistry) {
	t.Helper()
	t1, t2, t3 := &stubTunnel{id: "u1"}, &stubTunnel{id: "u2"}, &stubTunnel{id: "u3"}
	reg := &countingRegistry{stubRegistry: &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": t1, "u2": t2},
		healthy: []tunnel.Tunnel{t1, t2, t3},
		health:  map[string]bool{"u1": true, "u2": true, "u3": true},
		lat:     map[string]time.Duration{"u3": 50 * time.Millisecond},
	}}
	return mkService(t, reg), reg
}

func TestPreferOrderQueryBudget(t *testing.T) {
	svc, reg := countingService(t)
	svc.SetLatencyRouting(true, 0)

	svc.candidates("warp-aaaa", "u1") // 首次：建立黏住目標
	svc.rememberSticky("warp-aaaa", "u3")
	reg.reset()

	svc.candidates("warp-aaaa", "u1")

	// 延遲隨排序清單一併交付：全域選路對註冊表的查詢必須恰好一次。
	if n := reg.rankCalls.Load(); n != 1 {
		t.Errorf("健康排序清單應只取一次: %d", n)
	}
	if n := reg.healthCalls.Load(); n != 0 {
		t.Errorf("全域模式不應查綁定健康狀態: %d", n)
	}
}

func TestBoundOrderQueryBudget(t *testing.T) {
	svc, reg := countingService(t)
	svc.SetLatencyRouting(false, 0)
	reg.reset()

	svc.candidates("warp-aaaa", "u1")

	if n := reg.rankCalls.Load(); n != 1 {
		t.Errorf("健康排序清單應只取一次: %d", n)
	}
	if n := reg.healthCalls.Load(); n != 1 {
		t.Errorf("綁定健康查詢應只做一次: %d", n)
	}
}

// fixedRegistry 預建排序清單：benchmark 只量 dispatcher 自身成本，
// 不把測試假物每輪重組清單的開銷算進去。
type fixedRegistry struct {
	*stubRegistry
	list []tunnel.Ranked
}

func (r *fixedRegistry) HealthyRanked() []tunnel.Ranked { return r.list }

func benchRegistry(lat map[string]time.Duration) *fixedRegistry {
	t1, t2, t3 := &stubTunnel{id: "u1"}, &stubTunnel{id: "u2"}, &stubTunnel{id: "u3"}
	stub := &stubRegistry{
		bound:   map[string]tunnel.Tunnel{"u1": t1},
		healthy: []tunnel.Tunnel{t1, t2, t3},
		health:  map[string]bool{"u1": true, "u2": true, "u3": true},
		lat:     lat,
	}
	return &fixedRegistry{stubRegistry: stub, list: mkRanked(stub.healthy, lat)}
}

func BenchmarkCandidatesPrefer(b *testing.B) {
	reg := benchRegistry(map[string]time.Duration{"u3": 50 * time.Millisecond})
	svc := &Service{registry: reg, sticky: map[string]string{"warp-aaaa": "u3"}, prefer: true}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		svc.candidates("warp-aaaa", "u1")
	}
}

func BenchmarkCandidatesBound(b *testing.B) {
	reg := benchRegistry(map[string]time.Duration{"u1": 10 * time.Millisecond})
	svc := &Service{registry: reg, sticky: map[string]string{}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		svc.candidates("warp-aaaa", "u1")
	}
}
