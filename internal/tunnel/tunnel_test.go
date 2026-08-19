package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
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

	// 後續低延遲探測可恢復使用；延遲為 EMA 平滑值（向 10ms 收斂：0.3*10+0.7*120=87ms）。
	m.RecordProbe("u1", nil, 10*time.Millisecond)
	st = m.States()["u1"]
	if !st.Healthy || st.ConsecutiveFails != 0 || st.LastError != "" {
		t.Errorf("低延遲恢復後狀態錯誤: %+v", st)
	}
	approxMS(t, st.LastLatency, 87*time.Millisecond)
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

// TestLatencyProbeDisabled 默認（未設定間隔）不啟動獨立循環：
// 啟動首輪探測（v1.6.9 起）應執行一次，但其後（interval=1h）不再有探測。
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

	// 等待啟動首輪完成
	deadline := time.Now().Add(time.Second)
	for probes.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	base := probes.Load()
	if base < 1 {
		t.Fatal("啟動應立即執行首輪探測")
	}
	time.Sleep(200 * time.Millisecond)
	if got := probes.Load(); got != base {
		t.Fatalf("interval=1h 下首輪後不應再探測, base=%d got=%d", base, got)
	}
}

// --- v1.6.5：延遲排序選路 + 健康參數熱重載 ---

// TestHealthySortedByLatency 健康隧道按最近探測延遲升序；
// 未探測（延遲未知）殿後；同值保持配置順序。
func TestHealthySortedByLatency(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{
		mkUpstream("u1", true), mkUpstream("u2", true), mkUpstream("u3", true),
	}); err != nil {
		t.Fatal(err)
	}
	m.RecordProbe("u1", nil, 120*time.Millisecond)
	m.RecordProbe("u2", nil, 50*time.Millisecond)
	// u3 未探測 → 殿後；u2(50) < u1(120)
	got := m.HealthySortedByLatency()
	want := []string{"u2", "u1", "u3"}
	if len(got) != len(want) {
		t.Fatalf("應返回 3 條, got %d", len(got))
	}
	for i, id := range want {
		if got[i].ID() != id {
			t.Errorf("順序[%d] = %s, want %s", i, got[i].ID(), id)
		}
	}

	// 同值穩定保序：u3 探測為 50ms 與 u2 相同 → u2 在前（配置順序）
	m.RecordProbe("u3", nil, 50*time.Millisecond)
	got = m.HealthySortedByLatency()
	want = []string{"u2", "u3", "u1"}
	for i, id := range want {
		if got[i].ID() != id {
			t.Errorf("同值保序[%d] = %s, want %s", i, got[i].ID(), id)
		}
	}
}

// TestHealthySortedByLatencyExcludesUnhealthy 不健康/停用的隧道不在清單。
func TestHealthySortedByLatencyExcludesUnhealthy(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 2)
	if err := m.Sync(context.Background(), []*config.Upstream{
		mkUpstream("u1", true), mkUpstream("u2", true), mkUpstream("u3", false),
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		m.RecordProbe("u2", errors.New("fail"), 0)
	}
	m.RecordProbe("u1", nil, 10*time.Millisecond)
	got := m.HealthySortedByLatency()
	if len(got) != 1 || got[0].ID() != "u1" {
		t.Errorf("應僅剩健康的 u1, got %v", got)
	}
}

// TestApplyHealthHotSwapsThreshold ApplyHealth 運行中熱套閾值：
// 初始 3 → 套用 1 後單次失敗即不健康。
func TestApplyHealthHotSwapsThreshold(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	m.ApplyHealth(time.Hour, 1, 0, 0)
	m.RecordProbe("u1", errors.New("fail"), 0)
	if st := m.States()["u1"]; st.Healthy || st.ConsecutiveFails != 1 {
		t.Errorf("threshold=1 時單次失敗應不健康: %+v", st)
	}
}

// TestApplyHealthHotSwapsLatencyMax ApplyHealth 同步熱套延遲丟棄門檻。
func TestApplyHealthHotSwapsLatencyMax(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 2)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	m.ApplyHealth(time.Hour, 2, 50*time.Millisecond, 0)
	m.RecordProbe("u1", nil, 80*time.Millisecond)
	if st := m.States()["u1"]; st.ConsecutiveFails != 1 {
		t.Errorf("超過熱套後的門檻應計為失敗: %+v", st)
	}
}

// TestApplyHealthRebuildsTickers 巡檢運行中熱套 interval：
// 500ms → 25ms 後，短時間內探測次數應顯著增加。
func TestApplyHealthRebuildsTickers(t *testing.T) {
	var created []*fakeTunnel
	var probes atomic.Int64
	probeFn := func(ctx context.Context, d Dialer) (time.Duration, error) {
		probes.Add(1)
		return time.Millisecond, nil
	}
	m := NewManager(fakeFactory(&created), probeFn, 500*time.Millisecond, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	time.Sleep(150 * time.Millisecond) // 舊節奏（500ms）下至多 1 次
	before := probes.Load()
	m.ApplyHealth(25*time.Millisecond, 3, 0, 0)

	deadline := time.Now().Add(2 * time.Second)
	for probes.Load()-before < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := probes.Load() - before; got < 3 {
		t.Fatalf("熱套 interval=25ms 後應快速累積探測,新增 %d 次", got)
	}
}

// TestApplyHealthStartsLatencyLoop 運行中從 0 打開獨立延遲探測循環。
func TestApplyHealthStartsLatencyLoop(t *testing.T) {
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

	// 啟動首輪探測完成後取基線（v1.6.9 起啟動即探）
	deadline := time.Now().Add(time.Second)
	for probes.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	base := probes.Load()
	if base < 1 {
		t.Fatal("前置條件：啟動首輪應完成")
	}
	m.ApplyHealth(time.Hour, 3, 0, 30*time.Millisecond)

	deadline = time.Now().Add(2 * time.Second)
	for probes.Load()-base < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := probes.Load() - base; got < 2 {
		t.Fatalf("熱套 probeIvl=30ms 後應啟動獨立循環, 新增=%d", got)
	}
}

// blockTunnel 手動重建可阻塞的假隧道：用於觀測「重建中」窗口。
type blockTunnel struct {
	fakeTunnel
	rebuildEnter chan struct{}
	rebuildGate  chan struct{}
}

func (b *blockTunnel) Rebuild(ctx context.Context) error {
	b.rebuild.Add(1)
	if b.rebuildEnter != nil {
		b.rebuildEnter <- struct{}{}
		<-b.rebuildGate
	}
	return nil
}

// waitState 輪詢直到條件成立或超時。
func waitState(t *testing.T, m *Manager, id string, ok func(State) bool) State {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		st := m.States()[id]
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("等待狀態超時: %+v", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManualRebuildExposesFlagAndClearsLatency(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Second, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}

	// 先有成功探測，累積舊延遲
	m.RecordProbe("u1", nil, 120*time.Millisecond)
	if st := m.States()["u1"]; st.LastLatency != 120*time.Millisecond {
		t.Fatalf("前置: LastLatency = %v", st.LastLatency)
	}

	// 換成可阻塞版本：直接改 entries 內隧道（避開 factory）不可行，改用 Manager.Rebuild 於背景跑
	bt := &blockTunnel{
		rebuildEnter: make(chan struct{}, 1),
		rebuildGate:  make(chan struct{}),
	}
	bt.id = "u1"
	bt.fp.Store(created[0].fp.Load())
	// 替換 entries 中的隧道（測試專用；經 States 觀測的行為不變）
	m.mu.Lock()
	m.entries["u1"].tunnel = bt
	m.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- m.Rebuild(context.Background(), "u1") }()

	<-bt.rebuildEnter // 重建已進入
	st := waitState(t, m, "u1", func(s State) bool { return s.Rebuilding })
	if !st.Rebuilding {
		t.Fatal("重建期間 State.Rebuilding 應為 true")
	}
	close(bt.rebuildGate) // 放行
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st = waitState(t, m, "u1", func(s State) bool { return !s.Rebuilding })
	if st.Rebuilding {
		t.Fatal("重建結束後 State.Rebuilding 應為 false")
	}
	if st.LastLatency != 0 {
		t.Errorf("重建成功後 LastLatency 應歸零（延遲未知待重探）, got %v", st.LastLatency)
	}
}

func TestAutoRebuildFlagLifecycle(t *testing.T) {
	var created []*fakeTunnel
	probeCalls := func(ctx context.Context, d Dialer) (time.Duration, error) {
		return 0, errProbeFail
	}
	m := NewManager(fakeFactory(&created), probeCalls, 30*time.Second, 2)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	// 先累積成功延遲
	m.RecordProbe("u1", nil, 90*time.Millisecond)

	m.RecordProbe("u1", errProbeFail, 0)
	m.RecordProbe("u1", errProbeFail, 0) // 達閾值 → 不健康 + 自動重建

	st := waitState(t, m, "u1", func(s State) bool { return s.Rebuilds >= 1 })
	if st.Rebuilds < 1 {
		t.Fatalf("應已觸發自動重建: %+v", st)
	}
	// 自動重建為背景 goroutine；結束後旗標清除、延遲歸零
	st = waitState(t, m, "u1", func(s State) bool { return !s.Rebuilding })
	if st.Rebuilding {
		t.Fatal("自動重建結束後 Rebuilding 應為 false")
	}
	if st.LastLatency != 0 {
		t.Errorf("自動重建後 LastLatency 應歸零, got %v", st.LastLatency)
	}
}

var errProbeFail = errors.New("probe fail")

// TestProbeAllParallel probeAll 應並行探測：3 條隧道各 300ms 探測，
// 串行需 ≥900ms；並行應 <600ms（閾值留有 CI 慢機餘裕）且全部生效。
func TestProbeAllParallel(t *testing.T) {
	var created []*fakeTunnel
	probe := func(ctx context.Context, d Dialer) (time.Duration, error) {
		time.Sleep(300 * time.Millisecond)
		return 250 * time.Millisecond, nil
	}
	m := NewManager(fakeFactory(&created), probe, 30*time.Second, 3)
	ups := []*config.Upstream{mkUpstream("u1", true), mkUpstream("u2", true), mkUpstream("u3", true)}
	if err := m.Sync(context.Background(), ups); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	m.probeAll(context.Background())
	elapsed := time.Since(start)

	if elapsed >= 600*time.Millisecond {
		t.Errorf("並行探測整輪應 <600ms（串行需 ≥900ms）, got %v", elapsed)
	}
	for _, id := range []string{"u1", "u2", "u3"} {
		if st := m.States()[id]; st.LastLatency != 250*time.Millisecond {
			t.Errorf("隧道 %s 延遲未記錄: %+v", id, st)
		}
	}
}

// approxMS 允許 ±1ms 的浮點截斷誤差比較。
func approxMS(t *testing.T, got, want time.Duration) {
	t.Helper()
	if d := got - want; d > time.Millisecond || d < -time.Millisecond {
		t.Errorf("延遲 = %v, want ~%v (±1ms)", got, want)
	}
}

// TestRecordProbeEMASmoothing 探測延遲以 EMA（α=0.3）平滑存儲：
// 排序與漂移用的讀數不應被單次 DNS/TLS 抖動拉動，否則全域模式會假漂移擺動。
func TestRecordProbeEMASmoothing(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Second, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}

	// 首次成功探測：原始值
	m.RecordProbe("u1", nil, 100*time.Millisecond)
	approxMS(t, m.States()["u1"].LastLatency, 100*time.Millisecond)

	// 單次尖峰 300ms：EMA = 0.3*300 + 0.7*100 = 160ms（遠低於原始 300）
	m.RecordProbe("u1", nil, 300*time.Millisecond)
	approxMS(t, m.States()["u1"].LastLatency, 160*time.Millisecond)

	// 回落 100ms：EMA = 0.3*100 + 0.7*160 = 142ms
	m.RecordProbe("u1", nil, 100*time.Millisecond)
	approxMS(t, m.States()["u1"].LastLatency, 142*time.Millisecond)

	// 單次尖峰的移動量（100→160）遠小於原始尖峰（300），小於默認容差 20ms 場景下的擺動源
	if d := m.States()["u1"].LastLatency - 100*time.Millisecond; d >= 60*time.Millisecond {
		t.Errorf("EMA 對單次尖峰過於敏感: %v", d)
	}
}

// TestRecordProbeDiscardUsesRawValue latency_discard 判定用原始值（非 EMA）：
// 平滑不應稀釋尖峰的丟棄判定。
func TestRecordProbeDiscardUsesRawValue(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, 30*time.Second, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	m.SetLatencyMax(200 * time.Millisecond)

	// 首次 100ms 正常
	m.RecordProbe("u1", nil, 100*time.Millisecond)
	// 原始 300ms 超過門檻 200ms → 應計為失敗（儘管 EMA 後僅 160ms）
	m.RecordProbe("u1", nil, 300*time.Millisecond)
	st := m.States()["u1"]
	if st.ConsecutiveFails != 1 {
		t.Errorf("丟棄判定應使用原始值: fails=%d, last_error=%q", st.ConsecutiveFails, st.LastError)
	}
}

// TestRunProbesImmediately Run 啟動應立即執行首輪探測（不等首個 ticker）：
// 延遲優選與健康判定依賴探測數據；啟動後前 interval 秒不應退化為配置順序。
func TestRunProbesImmediately(t *testing.T) {
	var created []*fakeTunnel
	var probes atomic.Int64
	probe := func(ctx context.Context, d Dialer) (time.Duration, error) {
		probes.Add(1)
		return 30 * time.Millisecond, nil
	}
	m := NewManager(fakeFactory(&created), probe, 30*time.Second, 3)
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	deadline := time.Now().Add(500 * time.Millisecond)
	for probes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("啟動後 500ms 內應完成首輪探測（不應等待 30s ticker）")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := m.States()["u1"]; st.LastLatency != 30*time.Millisecond {
		t.Errorf("首輪探測應記錄延遲: %+v", st)
	}
}

// TestProbeTargetIsIPLiteral 探測目標必須是 IP 直連：域名目標會在每輪探測
// 經隧道 DNS（快取 TTL 60s vs 探測間隔更短 → 交替多付 DNS 往返），污染
// 延遲量測並在排序中引入系統性抖動。IP 直連量測純路徑延遲（TCP+TLS+HTTP）。
func TestProbeTargetIsIPLiteral(t *testing.T) {
	u, err := url.Parse(probeURL)
	if err != nil {
		t.Fatalf("probeURL 無法解析: %v", err)
	}
	if net.ParseIP(u.Hostname()) == nil {
		t.Errorf("探測目標應為 IP 字面值（免隧道 DNS）, got %q", u.Hostname())
	}
	if !strings.HasSuffix(u.Path, "/cdn-cgi/trace") {
		t.Errorf("探測路徑應為 Cloudflare trace 端點, got %q", u.Path)
	}
}
