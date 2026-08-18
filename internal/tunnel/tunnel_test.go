package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"multi-cf-proxy/internal/config"
)

// fakeTunnel 可腳本化的假隧道。
type fakeTunnel struct {
	id      string
	fp      atomic.Value
	dials   atomic.Int64
	rebuild atomic.Int64
	stops   atomic.Int64
	starts  atomic.Int64
	dnsTTL  atomic.Value // time.Duration（SetDNSCacheTTL 收到的值）
	dialErr error
}

func (f *fakeTunnel) ID() string { return f.id }
func (f *fakeTunnel) State() State {
	return State{ID: f.id, Rebuilds: f.rebuild.Load()}
}
func (f *fakeTunnel) Fingerprint() string {
	if v, ok := f.fp.Load().(string); ok {
		return v
	}
	return ""
}
func (f *fakeTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.dials.Add(1)
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	c1, c2 := net.Pipe()
	go func() { // 模擬遠端不斷開
		buf := make([]byte, 1)
		for {
			if _, err := c2.Read(buf); err != nil {
				return
			}
		}
	}()
	return c1, nil
}
func (f *fakeTunnel) Start(ctx context.Context) error { f.starts.Add(1); return nil }
func (f *fakeTunnel) Stop()                           { f.stops.Add(1) }
func (f *fakeTunnel) Rebuild(ctx context.Context) error {
	f.rebuild.Add(1)
	return nil
}

func fakeFactory(created *[]*fakeTunnel) Factory {
	var mu sync.Mutex
	return func(u *config.Upstream) (Tunnel, error) {
		ft := &fakeTunnel{id: u.ID}
		ft.fp.Store(u.PrivateKey + "|" + u.PeerPublicKey + "|" + u.Endpoint + "|" + fmt.Sprint(u.Addresses))
		mu.Lock()
		*created = append(*created, ft)
		mu.Unlock()
		return ft, nil
	}
}

func mkUpstream(id string, enabled bool) *config.Upstream {
	return &config.Upstream{ID: id, Name: "n-" + id, Enabled: enabled}
}

func TestSyncCreatesStartsRemoves(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Millisecond, 3)

	ups := []*config.Upstream{mkUpstream("u1", true), mkUpstream("u2", false), mkUpstream("u3", true)}
	if err := m.Sync(context.Background(), ups); err != nil {
		t.Fatal(err)
	}
	if len(created) != 3 {
		t.Fatalf("應建立 3 條隧道: %d", len(created))
	}
	if created[0].starts.Load() != 1 || created[2].starts.Load() != 1 {
		t.Error("啟用的上游應 Start")
	}
	if created[1].starts.Load() != 0 {
		t.Error("停用的上游不應 Start")
	}

	// 移除 u3、u2 停用→保持存在但停止、新增 u4
	ups2 := []*config.Upstream{mkUpstream("u1", true), mkUpstream("u2", true), mkUpstream("u4", true)}
	if err := m.Sync(context.Background(), ups2); err != nil {
		t.Fatal(err)
	}
	if created[2].stops.Load() != 1 {
		t.Error("被移除的上游應 Stop")
	}
	if _, ok := m.Get("u3"); ok {
		t.Error("u3 應已移除")
	}
	if _, ok := m.Get("u4"); !ok {
		t.Error("u4 應存在")
	}
	if created[0].stops.Load() != 0 {
		t.Error("未變動的隧道不應被重建/停止")
	}
}

func TestSyncRebuildOnConfigChange(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Millisecond, 3)
	m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)})

	// 私鑰變化 → 應重建而非復用
	up := mkUpstream("u1", true)
	up.PrivateKey = "changed"
	m.Sync(context.Background(), []*config.Upstream{up})
	if created[0].rebuild.Load() != 1 {
		t.Error("隧道配置變化應觸發 Rebuild")
	}
}

func TestHealthyList(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Millisecond, 3)
	m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true), mkUpstream("u2", true)})

	// u2 連續失敗達閾值 → 不健康
	for i := 0; i < 3; i++ {
		m.RecordProbe("u2", errors.New("probe fail"), 0)
	}

	ones := m.Healthy()
	if len(ones) != 1 || ones[0].ID() != "u1" {
		t.Errorf("Healthy() = %v", ones)
	}
	st := m.States()["u2"]
	if st.Healthy || st.ConsecutiveFails != 3 {
		t.Errorf("u2 狀態 = %+v", st)
	}

	// 單次失敗未達閾值不應轉不健康
	m.RecordProbe("u1", errors.New("one fail"), 0)
	if !m.States()["u1"].Healthy {
		t.Error("單次失敗不應立即轉不健康")
	}
}

// TestLatencyDiscardThreshold 超過延遲門檻視為探測失敗；
// 達既有連續失敗閾值才從健康池丟棄，低延遲探測可恢復。
func TestLatencyDiscardThreshold(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Millisecond, 2)
	m.SetLatencyMax(50 * time.Millisecond)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}

	// 首次超標：記錄實測延遲並計為失敗，但未達閾值仍可用。
	m.RecordProbe("u1", nil, 120*time.Millisecond)
	st := m.States()["u1"]
	if !st.Healthy || st.ConsecutiveFails != 1 || st.LastLatency != 120*time.Millisecond {
		t.Fatalf("首次超標狀態錯誤: %+v", st)
	}
	if !strings.Contains(st.LastError, "超過") {
		t.Errorf("超標應留下原因: %q", st.LastError)
	}

	// 第二次超標達閾值：不健康、從 Healthy 池排除，並排程重建。
	m.RecordProbe("u1", nil, 120*time.Millisecond)
	st = m.States()["u1"]
	if st.Healthy || st.ConsecutiveFails != 2 || st.Rebuilds != 1 {
		t.Fatalf("達閾值後應丟棄並重建: %+v", st)
	}
	if got := m.Healthy(); len(got) != 0 {
		t.Errorf("延遲過高的上游不應留在健康池: %v", got)
	}

	// 後續低延遲探測可恢復使用。
	m.RecordProbe("u1", nil, 10*time.Millisecond)
	st = m.States()["u1"]
	if !st.Healthy || st.ConsecutiveFails != 0 || st.LastError != "" || st.LastLatency != 10*time.Millisecond {
		t.Errorf("低延遲恢復後狀態錯誤: %+v", st)
	}
}

func TestLatencyDiscardDisabled(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Millisecond, 2)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}

	// 未設定門檻（0=停用）時，再高的成功量測都不應被丟棄。
	m.RecordProbe("u1", nil, 5*time.Second)
	st := m.States()["u1"]
	if !st.Healthy || st.ConsecutiveFails != 0 || st.LastError != "" || st.LastLatency != 5*time.Second {
		t.Errorf("停用延遲丟棄後狀態錯誤: %+v", st)
	}
}

// TestHealthLoopAutoRebuild 核心行為：連續探測失敗達閾值 → 標記不健康 + 自動重建；
// 恢復成功 → 恢復健康。
func TestHealthLoopAutoRebuild(t *testing.T) {
	var created []*fakeTunnel
	var probeMu sync.Mutex
	probeFail := true
	probe := func(ctx context.Context, d Dialer) (time.Duration, error) {
		probeMu.Lock()
		f := probeFail
		probeMu.Unlock()
		if f {
			return 0, errors.New("probe fail")
		}
		return 10 * time.Millisecond, nil
	}
	m := NewManager(fakeFactory(&created), probe, 20*time.Millisecond, 3)
	m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st := m.States()["u1"]
		if created[0].rebuild.Load() >= 1 && !st.Healthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if created[0].rebuild.Load() < 1 {
		t.Fatalf("連續失敗應觸發自動重建, rebuilds=%d", created[0].rebuild.Load())
	}
	st := m.States()["u1"]
	if st.Healthy {
		t.Error("失敗達閾值後應標記不健康")
	}

	// 恢復
	probeMu.Lock()
	probeFail = false
	probeMu.Unlock()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if m.States()["u1"].Healthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !m.States()["u1"].Healthy {
		t.Error("探測恢復後應回到健康")
	}
}

func TestStopAll(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Millisecond, 3)
	m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)})
	m.StopAll()
	if created[0].stops.Load() != 1 {
		t.Error("StopAll 應停止全部隧道")
	}
}

// --- v1.6 修復：Web「重建」按鈕繞過狀態機 ---

// TestManagerManualRebuild 手動重建應走狀態機：計數 +1、重置健康狀態與錯誤。
func TestManagerManualRebuild(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 3) // 不跑巡檢
	ups := []*config.Upstream{mkUpstream("u1", true)}
	if err := m.Sync(context.Background(), ups); err != nil {
		t.Fatal(err)
	}

	// 打成不健康（3 連敗觸發自動重建，异步；手動重建以 rebuilding 互斥）
	for i := 0; i < 3; i++ {
		m.RecordProbe("u1", errors.New("probe fail"), 0)
	}
	st := m.States()["u1"]
	if st.Healthy {
		t.Fatal("前置條件：應已不健康")
	}

	if err := m.Rebuild(context.Background(), "u1"); err != nil {
		t.Fatalf("手動重建失敗: %v", err)
	}
	st = m.States()["u1"]
	if st.Rebuilds < 1 {
		t.Errorf("手動重建應計入 Rebuilds, got %d", st.Rebuilds)
	}
	if !st.Healthy || st.ConsecutiveFails != 0 || st.LastError != "" {
		t.Errorf("手動重建後應重置健康狀態: %+v", st)
	}
	if created[0].rebuild.Load() < 1 {
		t.Error("底層隧道應被重建")
	}
}

// TestManagerManualRebuildDisabled 停用的上游不可手動重建（避免喚醒 Manager 認為已停的隧道）。
func TestManagerManualRebuildDisabled(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", false)}); err != nil {
		t.Fatal(err)
	}
	err := m.Rebuild(context.Background(), "u1")
	if !errors.Is(err, ErrTunnelNotRunning) {
		t.Fatalf("停用上游應返回 ErrTunnelNotRunning, got %v", err)
	}
	if created[0].rebuild.Load() != 0 || created[0].starts.Load() != 0 {
		t.Error("停用上游不應被觸碰")
	}
}

// TestManagerManualRebuildMissing 不存在的上游返回 ErrTunnelNotFound。
func TestManagerManualRebuildMissing(t *testing.T) {
	m := NewManager(fakeFactory(&[]*fakeTunnel{}), nil, time.Hour, 3)
	if err := m.Rebuild(context.Background(), "nope"); !errors.Is(err, ErrTunnelNotFound) {
		t.Fatalf("應返回 ErrTunnelNotFound, got %v", err)
	}
}

// --- v1.6 R3：獨立可調延遲探測循環 ---

// TestLatencyProbeLoop 設定獨立探測間隔後，健康循環外另有更高頻探測（更新延遲）。
func TestLatencyProbeLoop(t *testing.T) {
	var created []*fakeTunnel
	var probes atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		probes.Add(1)
		return 7 * time.Millisecond, nil
	}
	m := NewManager(fakeFactory(&created), probeFn, time.Hour, 3) // 健康循環 1h 不觸發
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	m.SetLatencyProbeInterval(40 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for probes.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := probes.Load(); got < 3 {
		t.Fatalf("獨立循環應更高頻探測, probes=%d", got)
	}
	st := m.States()["u1"]
	if st.LastLatency != 7*time.Millisecond {
		t.Errorf("LastLatency = %v, want 7ms", st.LastLatency)
	}
}

// TestLatencyProbeDisabled 默認（未設定間隔）不啟動獨立循環。
func TestLatencyProbeDisabled(t *testing.T) {
	var created []*fakeTunnel
	var probes atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		probes.Add(1)
		return time.Millisecond, nil
	}
	m := NewManager(fakeFactory(&created), probeFn, time.Hour, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	if got := probes.Load(); got != 0 {
		t.Fatalf("未設定間隔時不應有探測, probes=%d", got)
	}
}
