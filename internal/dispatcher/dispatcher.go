// Package dispatcher 入站鑑權與選路：帳密 → 綁定上游 → failover 容錯切換。
package dispatcher

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	// IsHealthy 查詢指定上游健康狀態。
	IsHealthy(upstreamID string) bool
}

// Service 鑑權選路服務。
type Service struct {
	auth        *auth.Store
	registry    Registry
	stats       *stats.Collector
	dialTimeout time.Duration
}

// NewService 建立服務；dialTimeout 為單次上游撥號超時（默認 15 秒）。
func NewService(a *auth.Store, r Registry, s *stats.Collector) *Service {
	return &Service{auth: a, registry: r, stats: s, dialTimeout: 15 * time.Second}
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

	candidates := s.candidates(up.ID)
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
		return s.stats.WrapConn(conn, t.ID(), username), t.ID(), nil
	}
	return nil, "", fmt.Errorf("全部候選上游撥號失敗，最後錯誤: %w", lastErr)
}

// candidates 依「綁定優先、其餘健康上游依序備援」生成嘗試順序（去重）。
func (s *Service) candidates(boundID string) []tunnel.Tunnel {
	healthy := s.registry.Healthy()
	var out []tunnel.Tunnel
	seen := map[string]bool{}

	if t, ok := s.registry.Bound(boundID); ok && s.registry.IsHealthy(boundID) {
		out = append(out, t)
		seen[boundID] = true
	}
	for _, t := range healthy {
		if seen[t.ID()] {
			continue
		}
		out = append(out, t)
		seen[t.ID()] = true
	}
	return out
}
