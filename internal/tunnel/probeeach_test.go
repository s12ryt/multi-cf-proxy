// 覆蓋 R8：巡檢迴圈的取鎖與配置契約。
// 行 18 probeEach 單次持鎖（不得分兩次取鎖讀 entries 與 interval）；行 52 快照型別；行 70 基準。
package tunnel

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// countingRWMutex 無法直接注入，改以「探測期間可取寫鎖」驗證鎖不被長期持有，
// 並以配置計數驗證容器數量。
//
// TestProbeEachSingleLockPass 探測快照只做一次：
// 取快照後 Manager 必須完全釋放鎖，讓 Sync/RecordProbe 不被巡檢阻塞。
func TestProbeEachSingleLockPass(t *testing.T) {
	var probes atomic.Int64
	gate := make(chan struct{})
	m := queryManager(t)
	m.probe = func(ctx context.Context, d Dialer) (time.Duration, error) {
		probes.Add(1)
		<-gate // 探測中：此時鎖必須已釋放
		return 5 * time.Millisecond, nil
	}

	done := make(chan struct{})
	go func() {
		m.probeAll(context.Background())
		close(done)
	}()

	for probes.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	locked := make(chan struct{})
	go func() {
		m.mu.Lock()
		m.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		t.Fatal("探測進行中仍持有 Manager 鎖")
	}
	close(gate)
	<-done
}

// TestProbeTargetsSnapshotAllocs 快照只應配置一個容器（原本為切片 + 映射兩個）。
func TestProbeTargetsSnapshotAllocs(t *testing.T) {
	m := queryManager(t)
	n := testing.AllocsPerRun(200, func() {
		m.probeTargets()
	})
	if n > 1 {
		t.Errorf("探測快照配置 %v 次（應僅 1 個容器）", n)
	}
}

// TestProbeTargetsCarriesBudget 快照同時交付 ctx 預算（省一次取鎖）。
func TestProbeTargetsCarriesBudget(t *testing.T) {
	m := queryManager(t)
	targets, budget := m.probeTargets()
	if len(targets) != 1 || targets[0].id != "u1" {
		t.Errorf("僅 u1 運行中: %v", targets)
	}
	if budget != m.probeBudget() {
		t.Errorf("預算 = %v, want %v", budget, m.probeBudget())
	}
}

func BenchmarkProbeTargets(b *testing.B) {
	m := queryManager(&testing.T{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.probeTargets()
	}
}
