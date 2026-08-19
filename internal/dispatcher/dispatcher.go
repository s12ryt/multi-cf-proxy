// Package dispatcher 入站鑑權與選路：帳密 → 綁定上游 → failover 容錯切換。
package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/stats"
	"multi-cf-proxy/internal/tunnel"
)

// 錯誤語意。
var (
	// ErrAuth 帳密錯誤或帳號不可用。
	ErrAuth = errors.New("認證失敗")
	// ErrNoHealthyUpstream 沒有任何可用的健康上游。
	ErrNoHealthyUpstream = errors.New("沒有健康的上游可用")
)

// Registry 上游查詢介面（由 tunnel.Manager 適配）。
type Registry interface {
	// Bound 返回帳號綁定的上游（不論健康狀態）。
	Bound(upstreamID string) (tunnel.Tunnel, bool)
	// Healthy 返回健康上游清單（按配置順序）。
	Healthy() []tunnel.Tunnel
	// HealthySortedByLatency 返回健康上游清單（按最近探測延遲升序，未知殿後）。
	HealthySortedByLatency() []tunnel.Tunnel
	// IsHealthy 查詢指定上游健康狀態。
	IsHealthy(upstreamID string) bool
	// LatencyOf 返回指定上游最近一次成功探測延遲；未知返回 false。
	LatencyOf(upstreamID string) (time.Duration, bool)
}

// Service 鑑權選路服務。
type Service struct {
	auth        *auth.Store
	registry    Registry
	stats       *stats.Collector
	dialTimeout time.Duration

	rmu    sync.Mutex
	prefer bool          // 全域延遲優先模式
	margin time.Duration // 切換容差（僅快超過此值才漂移；0 = 任何更快即切）
	sticky map[string]string
}

// NewService 建立服務；dialTimeout 為單次上游撥號超時（默認 15 秒）。
func NewService(a *auth.Store, r Registry, s *stats.Collector) *Service {
	return &Service{
		auth:        a,
		registry:    r,
		stats:       s,
		dialTimeout: 15 * time.Second,
		sticky:      map[string]string{},
	}
}

// SetLatencyRouting 熱套延遲優選設置（Web 設置保存即生效路徑）。
// prefer=false 時回到「綁定優先」行為；模式切換會清空黏住表（重新計算目標）。
func (s *Service) SetLatencyRouting(prefer bool, margin time.Duration) {
	s.rmu.Lock()
	s.prefer = prefer
	s.margin = margin
	s.sticky = map[string]string{}
	s.rmu.Unlock()
}

// Authenticate 僅驗帳密（入站協議認證階段的預檢；撥號仍走 Route）。
func (s *Service) Authenticate(username, password string) bool {
	_, ok := s.auth.Authenticate(username, password)
	return ok
}

// Route 鑑權並建立出站連線：返回計費連線與實際使用的上游 ID。
func (s *Service) Route(ctx context.Context, username, password, network, addr string) (net.Conn, string, error) {
	up, ok := s.auth.Authenticate(username, password)
	if !ok {
		return nil, "", fmt.Errorf("%w: 帳號或密碼錯誤（%s）", ErrAuth, username)
	}

	candidates := s.candidates(username, up.ID)
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("%w: 帳號 %s 綁定的上游 %s 不可用且無備援", ErrNoHealthyUpstream, username, up.ID)
	}

	var lastErr error
	for _, t := range candidates {
		dctx, cancel := context.WithTimeout(ctx, s.dialTimeout)
		start := time.Now()
		conn, err := t.DialContext(dctx, network, addr)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("上游 %s 撥號 %s 失敗: %w", t.ID(), addr, err)
			continue
		}
		s.stats.RecordDial(time.Since(start))
		s.rememberSticky(username, t.ID())
		return s.stats.WrapConn(conn, t.ID(), username), t.ID(), nil
	}
	return nil, "", fmt.Errorf("全部候選上游撥號失敗，最後錯誤: %w", lastErr)
}

// rememberSticky 全域優先模式下記錄帳號實際使用的出口（漂移/故障轉移後更新黏住目標）。
func (s *Service) rememberSticky(username, upstreamID string) {
	s.rmu.Lock()
	if s.prefer {
		s.sticky[username] = upstreamID
	}
	s.rmu.Unlock()
}

// candidates 生成嘗試順序：
//   - 默認：綁定上游健康時優先；備援清單按最近探測延遲升序（快者先試）。
//   - 全域延遲優先：忽略綁定，每帳號黏住當前出口；僅當其他上游快超過容差
//     （margin=0 時任何更快）才漂移；黏住上游不健康時立即改選最快。
func (s *Service) candidates(username, boundID string) []tunnel.Tunnel {
	sorted := s.registry.HealthySortedByLatency()

	s.rmu.Lock()
	prefer := s.prefer
	margin := s.margin
	stickyID := s.sticky[username]
	s.rmu.Unlock()

	if !prefer {
		var out []tunnel.Tunnel
		seen := map[string]bool{}
		if t, ok := s.registry.Bound(boundID); ok && s.registry.IsHealthy(boundID) {
			out = append(out, t)
			seen[boundID] = true
		}
		for _, t := range sorted {
			if !seen[t.ID()] {
				out = append(out, t)
				seen[t.ID()] = true
			}
		}
		return out
	}

	// 全域模式：決定本輪目標（黏住 → 容差漂移 → 失效取最快）
	target := ""
	if stickyID != "" && s.registry.IsHealthy(stickyID) {
		if l, ok := s.registry.LatencyOf(stickyID); ok {
			target = stickyID
			if len(sorted) > 0 {
				if fl, ok2 := s.registry.LatencyOf(sorted[0].ID()); ok2 && fl+margin < l {
					target = sorted[0].ID() // 快超過容差 → 漂移
				}
			}
		}
	}
	if target == "" && len(sorted) > 0 {
		target = sorted[0].ID() // 初始（或黏住失效/延遲未知）＝當前最快
	}

	var out []tunnel.Tunnel
	seen := map[string]bool{}
	if target != "" {
		for _, t := range sorted {
			if t.ID() == target {
				out = append(out, t)
				seen[target] = true
				break
			}
		}
	}
	for _, t := range sorted {
		if !seen[t.ID()] {
			out = append(out, t)
			seen[t.ID()] = true
		}
	}
	return out
}
