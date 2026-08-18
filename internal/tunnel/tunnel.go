// Package tunnel 管理多條 WARP 隧道的生命週期、健康探測與自動重建。
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"multi-cf-proxy/internal/config"
)

// 手動重建的語意錯誤（Web 層映射 HTTP 狀態碼）。
var (
	// ErrTunnelNotFound 指定上游不存在。
	ErrTunnelNotFound = errors.New("隧道不存在")
	// ErrTunnelNotRunning 上游停用或隧道未運行，不可手動重建。
	ErrTunnelNotRunning = errors.New("隧道未運行")
	// ErrRebuilding 重建已在進行中。
	ErrRebuilding = errors.New("正在重建")
)

// Dialer 出站撥號抽象（net.Conn 供應者）。
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// State 一條隧道的管理器視角狀態快照。
type State struct {
	ID               string        `json:"id"`
	Healthy          bool          `json:"healthy"`
	ConsecutiveFails int           `json:"consecutive_fails"`
	LastCheck        time.Time     `json:"last_check"`
	LastLatency      time.Duration `json:"last_latency_ms"`
	LastError        string        `json:"last_error"`
	Rebuilds         int64         `json:"rebuilds"`
	Running          bool          `json:"running"`
}

// Tunnel 一條隧道的最小介面；實作者負責底層連接的建立與重建。
type Tunnel interface {
	Dialer
	ID() string
	Start(ctx context.Context) error
	Stop()
	// Rebuild 以當前配置重建底層連接（Stop + Start 的原子版本）。
	Rebuild(ctx context.Context) error
	// Fingerprint 返回影響底層連接的配置指紋；變化時管理器觸發 Rebuild。
	Fingerprint() string
}

// Factory 隧道工廠；測試注入 fake，正式路徑產生 WireGuard 隧道。
type Factory func(u *config.Upstream) (Tunnel, error)

// ProbeFunc 健康探測函數：返回延遲或錯誤。
type ProbeFunc func(ctx context.Context, d Dialer) (time.Duration, error)

// DefaultProbe 經隧道訪問 Cloudflare trace 端點驗證连通性。
func DefaultProbe(ctx context.Context, d Dialer) (time.Duration, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return 0, err
	}
	transport := &http.Transport{DialContext: d.DialContext, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("trace 返回 HTTP %d", resp.StatusCode)
	}
	return time.Since(start), nil
}

type tunnelEntry struct {
	tunnel     Tunnel
	running    bool
	state      State
	rebuilding bool
}

// Manager 多隧道管理器。
type Manager struct {
	mu         sync.RWMutex
	factory    Factory
	probe      ProbeFunc
	interval   time.Duration
	threshold  int
	latencyMax time.Duration // 0 = 停用；超過時視為一次探測失敗
	dnsTTL     time.Duration // 經隧道 DNS 快取 TTL（0 = 停用）
	dnsTTLSet  bool          // SetDNSCacheTTL 被呼叫過（Sync 時套用到新建隧道）
	probeIvl   time.Duration // 獨立延遲探測間隔（0 = 隨健康循環）
	entries    map[string]*tunnelEntry
	order      []string // 保持配置順序
}

// SetLatencyMax 設定探測延遲丟棄門檻。0 表示停用。
// 超標量測會依既有 threshold 累積為探測失敗，避免單次尖峰直接切換上游。
func (m *Manager) SetLatencyMax(max time.Duration) {
	m.mu.Lock()
	m.latencyMax = max
	m.mu.Unlock()
}

// SetDNSCacheTTL 設定經隧道 DNS 結果的本機快取 TTL（0 = 停用）。
// 對既有與後續新建的隧道同時生效（重啟後由 main 依配置再次套用）。
func (m *Manager) SetDNSCacheTTL(d time.Duration) error {
	m.mu.Lock()
	m.dnsTTL = d
	m.dnsTTLSet = true
	setters := make([]dnsTTLSetter, 0, len(m.entries))
	for _, e := range m.entries {
		if s, ok := e.tunnel.(dnsTTLSetter); ok {
			setters = append(setters, s)
		}
	}
	m.mu.Unlock()
	for _, s := range setters {
		if err := s.SetDNSCacheTTL(d); err != nil {
			return err
		}
	}
	return nil
}

// NewManager 建立管理器。interval 為探測週期，threshold 為不健康判定閾值。
func NewManager(factory Factory, probe ProbeFunc, interval time.Duration, threshold int) *Manager {
	if probe == nil {
		probe = DefaultProbe
	}
	return &Manager{
		factory:   factory,
		probe:     probe,
		interval:  interval,
		threshold: threshold,
		entries:   map[string]*tunnelEntry{},
	}
}

// Sync 將隧道集合對齊到上游配置：新增/移除/啟停/配置變化重建。
func (m *Manager) Sync(ctx context.Context, upstreams []*config.Upstream) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := map[string]*config.Upstream{}
	for _, u := range upstreams {
		want[u.ID] = u
	}

	// 移除不再存在的
	for _, id := range m.order {
		if _, ok := want[id]; ok {
			continue
		}
		e := m.entries[id]
		if e.running {
			e.tunnel.Stop()
		}
		delete(m.entries, id)
	}
	newOrder := make([]string, 0, len(upstreams))

	var firstErr error
	for _, u := range upstreams {
		newOrder = append(newOrder, u.ID)
		e, exists := m.entries[u.ID]
		if !exists {
			t, err := m.factory(u)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("建立隧道 %s（%s）失敗: %w", u.ID, u.Name, err)
				}
				continue
			}
			// 套用運行時 DNS 快取 TTL（main 於 Sync 前設定）
			if m.dnsTTLSet {
				if s, ok := t.(dnsTTLSetter); ok {
					_ = s.SetDNSCacheTTL(m.dnsTTL)
				}
			}
			e = &tunnelEntry{tunnel: t}
			e.state = State{ID: u.ID, Healthy: true, LastCheck: time.Now()}
			m.entries[u.ID] = e
		}

		// 配置指紋變化 → 重建
		if e.running && e.tunnel.Fingerprint() != fingerprint(u) {
			if err := e.tunnel.Rebuild(ctx); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("重建隧道 %s 失敗: %w", u.ID, err)
			} else {
				e.state.Rebuilds++
			}
		}

		// 啟停對齊
		switch {
		case u.Enabled && !e.running:
			if err := e.tunnel.Start(ctx); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("啟動隧道 %s 失敗: %w", u.ID, err)
				}
			} else {
				e.running = true
				e.state.Running = true
				e.state.Healthy = true
				e.state.ConsecutiveFails = 0
			}
		case !u.Enabled && e.running:
			e.tunnel.Stop()
			e.running = false
			e.state.Running = false
		}
	}
	m.order = newOrder
	return firstErr
}

// Get 按 ID 取隧道。
func (m *Manager) Get(id string) (Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[id]
	if !ok {
		return nil, false
	}
	return e.tunnel, true
}

// Rebuild 手動重建指定上游的隧道（Web「重建」按鈕）。
// 與自動重建共用狀態機：計入 Rebuilds、重建成功後重置健康狀態；
// 停用/未運行的上游拒絕（避免喚醒 Manager 認為已停的隧道）；
// 若自動重建正在進行，等待其完成後再執行（按鈕語意：必定執行一次）。
func (m *Manager) Rebuild(ctx context.Context, id string) error {
	// 等待在途重建釋放（自動重建路徑可能正持有旗標）
	wait := time.NewTimer(0)
	defer wait.Stop()
	for {
		m.mu.Lock()
		e, ok := m.entries[id]
		if !ok {
			m.mu.Unlock()
			return fmt.Errorf("隧道 %s 不存在: %w", id, ErrTunnelNotFound)
		}
		if !e.running {
			m.mu.Unlock()
			return fmt.Errorf("上游 %s 未啟用: %w", id, ErrTunnelNotRunning)
		}
		if !e.rebuilding {
			e.rebuilding = true
			e.state.Rebuilds++
			t := e.tunnel
			m.mu.Unlock()
			err := m.doManualRebuild(ctx, e, t)
			if err != nil {
				return fmt.Errorf("重建隧道 %s 失敗: %w", id, err)
			}
			return nil
		}
		m.mu.Unlock()

		select {
		case <-ctx.Done():
			return fmt.Errorf("等待隧道 %s 在途重建時取消: %w", id, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// doManualRebuild 執行底層重建並收尾狀態（呼叫方已持有 rebuilding 旗標）。
func (m *Manager) doManualRebuild(ctx context.Context, e *tunnelEntry, t Tunnel) error {
	defer func() {
		m.mu.Lock()
		e.rebuilding = false
		m.mu.Unlock()
	}()
	if err := t.Rebuild(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	e.state.Healthy = true
	e.state.ConsecutiveFails = 0
	e.state.LastError = ""
	m.mu.Unlock()
	return nil
}

// Healthy 返回所有運行中且健康的隧道（按配置順序）。
func (m *Manager) Healthy() []Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Tunnel
	for _, id := range m.order {
		if e, ok := m.entries[id]; ok && e.running && e.state.Healthy {
			out = append(out, e.tunnel)
		}
	}
	return out
}

// States 返回全部隧道狀態快照。
func (m *Manager) States() map[string]State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]State, len(m.entries))
	for id, e := range m.entries {
		out[id] = e.state
	}
	return out
}

// RecordProbe 記錄一次探測結果：成功恢復健康；連續失敗（含延遲超標）
// 達閾值轉不健康並觸發自動重建。
func (m *Manager) RecordProbe(id string, probeErr error, latency time.Duration) {
	m.mu.Lock()
	e, ok := m.entries[id]
	if !ok {
		m.mu.Unlock()
		return
	}
	e.state.LastCheck = time.Now()
	if probeErr == nil {
		e.state.LastLatency = latency
		if m.latencyMax > 0 && latency > m.latencyMax {
			probeErr = fmt.Errorf("延遲 %s 超過丟棄閾值 %s", latency.Round(time.Millisecond), m.latencyMax.Round(time.Millisecond))
		} else {
			e.state.Healthy = true
			e.state.ConsecutiveFails = 0
			e.state.LastError = ""
			m.mu.Unlock()
			return
		}
	}
	e.state.ConsecutiveFails++
	e.state.LastError = probeErr.Error()
	if e.state.ConsecutiveFails >= m.threshold {
		e.state.Healthy = false
	}
	needRebuild := !e.state.Healthy && e.running && !e.rebuilding
	var t Tunnel
	if needRebuild {
		e.rebuilding = true
		e.state.Rebuilds++
		t = e.tunnel
	}
	m.mu.Unlock()

	if t != nil {
		go func() {
			defer func() {
				m.mu.Lock()
				e.rebuilding = false
				m.mu.Unlock()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = t.Rebuild(ctx)
		}()
	}
}

// SetLatencyProbeInterval 設定獨立延遲探測間隔（0 = 停用，延遲隨健康檢查更新）。
// 需於 Run 前呼叫（main 依配置設置，重啟生效）。
func (m *Manager) SetLatencyProbeInterval(d time.Duration) {
	m.mu.Lock()
	m.probeIvl = d
	m.mu.Unlock()
}

// Run 啟動健康巡檢循環（與可選的獨立延遲探測循環），直到 ctx 結束。
func (m *Manager) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	m.mu.RLock()
	probeIvl := m.probeIvl
	m.mu.RUnlock()

	latencyTick := make(chan time.Time, 1)
	if probeIvl > 0 {
		lt := time.NewTicker(probeIvl)
		defer lt.Stop()
		go func() {
			defer close(latencyTick)
			for {
				select {
				case <-ctx.Done():
					return
				case t := <-lt.C:
					select {
					case latencyTick <- t:
					default:
					}
				}
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeAll(ctx)
		case <-latencyTick:
			m.probeAll(ctx) // 同一探測路徑：更新延遲、計入丟棄與連續失敗判定
		}
	}
}

func (m *Manager) probeAll(ctx context.Context) {
	m.mu.RLock()
	ids := make([]string, 0, len(m.entries))
	dialers := make(map[string]Dialer, len(m.entries))
	for id, e := range m.entries {
		if e.running {
			ids = append(ids, id)
			dialers[id] = e.tunnel
		}
	}
	m.mu.RUnlock()

	probeTimeout := m.interval / 2
	if probeTimeout <= 0 || probeTimeout > 8*time.Second {
		probeTimeout = 8 * time.Second
	}
	for _, id := range ids {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		latency, err := m.probe(pctx, dialers[id])
		cancel()
		m.RecordProbe(id, err, latency)
	}
}

// StopAll 停止全部隧道（進程退出用）。
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.running {
			e.tunnel.Stop()
			e.running = false
			e.state.Running = false
		}
	}
}

// fingerprint 影響底層連接的欄位指紋。
func fingerprint(u *config.Upstream) string {
	return u.PrivateKey + "|" + u.PeerPublicKey + "|" + u.Endpoint + "|" + fmt.Sprint(u.Addresses)
}
