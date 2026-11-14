package tunnel

// 本檔覆蓋 A49（延遲專用探測循環與健康判定解耦）與 A50（probeTimeout clamp）。

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"multi-cf-proxy/internal/config"
)

// measureProbeBudget 量測 probeAll 給單次探測的 ctx 預算（A50/A58）。
func measureProbeBudget(t *testing.T, interval time.Duration) time.Duration {
	t.Helper()
	var got atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		if dl, ok := ctx.Deadline(); ok {
			got.Store(int64(time.Until(dl)))
		}
		return time.Millisecond, nil
	}
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), probeFn, interval, 1)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	m.probeAll(context.Background())
	return time.Duration(got.Load())
}

// TestProbeTimeoutClamp 探測預算 = clamp(interval*8/5, 6s, 10s)（A58）：
// 一輪探測最壞 = 冷握手 3×RTT + 穩態 1×RTT，DefaultProbe 全敗還要再跑一輪
// 加 0.5s 等待——舊公式（5s 間隔給 4s）裝不下兩輪，重試形同無效。
func TestProbeTimeoutClamp(t *testing.T) {
	cases := []struct {
		interval time.Duration
		want     time.Duration
	}{
		{5 * time.Second, 8 * time.Second},
		{2 * time.Second, 6 * time.Second},
		{30 * time.Second, 10 * time.Second},
		{0, 6 * time.Second},
	}
	for _, c := range cases {
		got := measureProbeBudget(t, c.interval)
		if got > c.want || got < c.want-500*time.Millisecond {
			t.Errorf("interval=%v 預算 = %v, want ≈%v", c.interval, got, c.want)
		}
	}
}

// latencyLoopManager 建立「健康循環不觸發（1h）+ 高頻延遲循環」的管理器。
func latencyLoopManager(t *testing.T, probeFn ProbeFunc, threshold int) *Manager {
	t.Helper()
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), probeFn, time.Hour, threshold)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	return m
}

// waitProbes 等到探測次數達 n。
func waitProbes(t *testing.T, probes *atomic.Int64, n int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for probes.Load() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := probes.Load(); got < n {
		t.Fatalf("探測次數 = %d, want >= %d", got, n)
	}
}

// TestLatencyProbeFailureDoesNotDegradeHealth A49：延遲專用循環的失敗
// 不累計連續失敗、不改健康、不觸發重建（健康判定只屬健康巡檢）。
func TestLatencyProbeFailureDoesNotDegradeHealth(t *testing.T) {
	var probes atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		if probes.Add(1) == 1 {
			return 5 * time.Millisecond, nil // 啟動首輪（健康路徑）成功
		}
		return 0, errors.New("探測失敗")
	}
	m := latencyLoopManager(t, probeFn, 1)
	m.SetLatencyProbeInterval(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitProbes(t, &probes, 4)

	st := m.States()["u1"]
	if !st.Healthy {
		t.Error("延遲循環失敗不應轉為不健康")
	}
	if st.ConsecutiveFails != 0 {
		t.Errorf("ConsecutiveFails = %d, want 0", st.ConsecutiveFails)
	}
	if st.Rebuilds != 0 {
		t.Errorf("Rebuilds = %d, want 0", st.Rebuilds)
	}
	if st.LastError != "" {
		t.Errorf("LastError = %q, want 空", st.LastError)
	}
}

// TestLatencyProbeIgnoresLatencyDiscard A49：延遲專用循環只更新 EMA，
// 超過丟棄門檻也不轉為探測失敗（丟棄判定只屬健康巡檢）。
func TestLatencyProbeIgnoresLatencyDiscard(t *testing.T) {
	var probes atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		if probes.Add(1) == 1 {
			return 5 * time.Millisecond, nil
		}
		return 200 * time.Millisecond, nil
	}
	m := latencyLoopManager(t, probeFn, 1)
	m.SetLatencyMax(50 * time.Millisecond)
	m.SetLatencyProbeInterval(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitProbes(t, &probes, 4)

	st := m.States()["u1"]
	if !st.Healthy || st.ConsecutiveFails != 0 {
		t.Errorf("超標延遲不應影響健康: healthy=%v fails=%d", st.Healthy, st.ConsecutiveFails)
	}
	if st.LastLatency <= 5*time.Millisecond {
		t.Errorf("LastLatency = %v, 應經 EMA 上升", st.LastLatency)
	}
}
