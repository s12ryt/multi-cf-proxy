package tunnel

// 本檔覆蓋重建風暴根治：
//   - 行 30-55：A60 重建期間探測豁免
//   - 行 57-115：A61 重建後就緒驗證（通/不通兩態）
//   - 行 117-200：A62 重建冷卻（寬限、最小間隔、冷卻內恢復、失敗亦冷卻、手動不受阻）

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"multi-cf-proxy/internal/config"
)

// rebuildManager 單上游 + 健康循環不自動觸發（1h）的管理器。
func rebuildManager(t *testing.T, probeFn ProbeFunc, threshold int) (*Manager, *fakeTunnel) {
	t.Helper()
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), probeFn, time.Hour, threshold)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	return m, created[0]
}

// waitRebuildIdle 等背景重建 goroutine 收尾。
func waitRebuildIdle(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !m.States()["u1"].Rebuilding {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("重建未在期限內收尾")
}

func failProbe() ProbeFunc {
	return func(ctx context.Context, d Dialer) (time.Duration, error) {
		return 0, errors.New("探測失敗")
	}
}

// TestProbeSkipsRebuildingTunnel A60：重建期間底層裝置為 nil，
// 探測必敗且只會污染失敗計數——該輪必須直接豁免。
func TestProbeSkipsRebuildingTunnel(t *testing.T) {
	var probes atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		probes.Add(1)
		return time.Millisecond, nil
	}
	m, _ := rebuildManager(t, probeFn, 3)

	m.mu.Lock()
	m.entries["u1"].rebuilding = true
	m.mu.Unlock()

	m.probeAll(context.Background())
	if got := probes.Load(); got != 0 {
		t.Errorf("重建中仍被探測 %d 次, want 0", got)
	}
}

// TestRebuildReadinessFailureKeepsUnhealthy A61：Rebuild 回報成功只代表
// 裝置已建立（Start 不等握手），就緒驗證不通時不得標回健康。
func TestRebuildReadinessFailureKeepsUnhealthy(t *testing.T) {
	m, ft := rebuildManager(t, failProbe(), 1)

	m.probeAll(context.Background())
	waitRebuildIdle(t, m)

	if got := ft.rebuild.Load(); got != 1 {
		t.Fatalf("Rebuild 次數 = %d, want 1", got)
	}
	st := m.States()["u1"]
	if st.Healthy {
		t.Error("就緒驗證失敗仍標健康")
	}
	if st.LastError == "" {
		t.Error("就緒驗證失敗未記錄 LastError")
	}
	if st.LastLatency != 0 {
		t.Errorf("LastLatency = %v, want 0（未知殿後）", st.LastLatency)
	}
}

// TestRebuildReadinessSuccessRestoresHealth A61：就緒驗證通過才恢復健康，
// 並以驗證所得延遲作為新隧道的起步讀數。
func TestRebuildReadinessSuccessRestoresHealth(t *testing.T) {
	var n atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		if n.Add(1) == 1 {
			return 0, errors.New("首輪失敗觸發重建")
		}
		return 7 * time.Millisecond, nil
	}
	m, _ := rebuildManager(t, probeFn, 1)

	m.probeAll(context.Background())
	waitRebuildIdle(t, m)

	st := m.States()["u1"]
	if !st.Healthy {
		t.Error("就緒驗證通過應恢復健康")
	}
	if st.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails = %d, want 0", st.ConsecutiveFails)
	}
	if st.LastError != "" {
		t.Errorf("LastError = %q, want 空", st.LastError)
	}
	if st.LastLatency != 7*time.Millisecond {
		t.Errorf("LastLatency = %v, want 7ms", st.LastLatency)
	}
}

// TestRebuildCooldownSuppressesStorm A62：重建完成後進入冷卻，
// 期間探測失敗既不累計也不再重建——否則 WireGuard 握手永遠被下一輪砍掉。
func TestRebuildCooldownSuppressesStorm(t *testing.T) {
	m, ft := rebuildManager(t, failProbe(), 1)

	m.probeAll(context.Background())
	waitRebuildIdle(t, m)

	for i := 0; i < 5; i++ {
		m.probeAll(context.Background())
	}
	if got := ft.rebuild.Load(); got != 1 {
		t.Errorf("冷卻期內重建 %d 次, want 1", got)
	}
	if got := m.States()["u1"].ConsecutiveFails; got != 0 {
		t.Errorf("冷卻期內 ConsecutiveFails = %d, want 0（不累計）", got)
	}
}

// TestRebuildFailureAlsoCoolsDown A62：Rebuild 本身失敗同樣進入冷卻，
// 否則底層持續建不起來時會每輪重試一次。
func TestRebuildFailureAlsoCoolsDown(t *testing.T) {
	m, ft := rebuildManager(t, failProbe(), 1)
	ft.rbErr.Store(errors.New("建立失敗"))

	m.probeAll(context.Background())
	waitRebuildIdle(t, m)

	for i := 0; i < 5; i++ {
		m.probeAll(context.Background())
	}
	if got := ft.rebuild.Load(); got != 1 {
		t.Errorf("重建失敗後冷卻期內又重建, 次數 = %d, want 1", got)
	}
}

// TestCooldownAllowsRecoveryOnSuccess A62：冷卻只抑制失敗側，
// 期間一次成功探測須立即恢復健康（恢復不應被延後 30 秒）。
func TestCooldownAllowsRecoveryOnSuccess(t *testing.T) {
	var n atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		if n.Add(1) <= 2 { // 1 = 健康巡檢、2 = 就緒驗證
			return 0, errors.New("探測失敗")
		}
		return 9 * time.Millisecond, nil
	}
	m, _ := rebuildManager(t, probeFn, 1)

	m.probeAll(context.Background())
	waitRebuildIdle(t, m)
	if m.States()["u1"].Healthy {
		t.Fatal("就緒驗證失敗後不該健康")
	}

	m.probeAll(context.Background())
	st := m.States()["u1"]
	if !st.Healthy || st.ConsecutiveFails != 0 || st.LastError != "" {
		t.Errorf("冷卻期內成功未恢復: healthy=%v fails=%d err=%q", st.Healthy, st.ConsecutiveFails, st.LastError)
	}
}

// TestManualRebuildBypassesCooldown A62：冷卻是自動重建的節流，
// 手動按鈕是使用者明示意圖，必定執行一次。
func TestManualRebuildBypassesCooldown(t *testing.T) {
	m, ft := rebuildManager(t, failProbe(), 1)

	m.probeAll(context.Background())
	waitRebuildIdle(t, m)

	if err := m.Rebuild(context.Background(), "u1"); err != nil {
		t.Fatalf("手動重建被冷卻阻擋: %v", err)
	}
	if got := ft.rebuild.Load(); got != 2 {
		t.Errorf("Rebuild 次數 = %d, want 2", got)
	}
}
