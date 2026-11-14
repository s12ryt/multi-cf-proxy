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
	// HealthyRanked 返回健康上游及其 EMA 平滑延遲（延遲升序，未知殿後）。
	HealthyRanked() []tunnel.Ranked
	// IsHealthy 查詢指定上游健康狀態。
	IsHealthy(upstreamID string) bool
}

// Service 鑑權選路服務。
type Service struct {
	auth        *auth.Store
	registry    Registry
	stats       *stats.Collector
	dialTimeout time.Duration

	rmu    sync.Mutex
	prefer bool              // 全域延遲優先模式
	margin time.Duration     // 延遲型換黏容差；0 = 僅不通才飄移
	sticky map[string]string // 帳號→黏住出口（參與選路：健康時恆為首選）
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

// SetLatencyRouting 熱套延遲優先模式與換黏容差（Web 設置保存即生效路徑）。
// prefer=false 時回到「綁定優先」行為；模式切換清空黏住表，單獨改容差則保留。
// marginMS=0 表示永不因延遲換黏——僅黏住出口不通時才飄移。
func (s *Service) SetLatencyRouting(prefer bool, marginMS int) {
	s.rmu.Lock()
	if s.prefer != prefer {
		s.sticky = map[string]string{}
	}
	s.prefer = prefer
	s.margin = time.Duration(marginMS) * time.Millisecond
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

// rememberSticky 全域優先模式下記錄帳號實際使用的出口（飄移/故障轉移後更新黏住目標）。
func (s *Service) rememberSticky(username, upstreamID string) {
	s.rmu.Lock()
	if s.prefer {
		s.sticky[username] = upstreamID
	}
	s.rmu.Unlock()
}

// EgressSnapshot 返回全域延遲優先模式下各帳號實際使用的出口映射（冪等快照）。
// 非全域模式返回空 map（帳號出口即其綁定上游，無漂移概念）。
func (s *Service) EgressSnapshot() map[string]string {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	out := make(map[string]string, len(s.sticky))
	for u, id := range s.sticky {
		out[u] = id
	}
	return out
}

// candidates 生成嘗試順序：
//   - 默認：綁定上游健康時優先；備援清單按最近探測延遲升序（快者先試）。
//   - 全域延遲優先：黏住出口健康時恆為首位；僅不通（或超出容差）才飄移，
//     其餘為撥號失敗時的降級序。
func (s *Service) candidates(username, boundID string) []tunnel.Tunnel {
	ranked := s.registry.HealthyRanked()

	s.rmu.Lock()
	prefer := s.prefer
	margin := s.margin
	cur := s.sticky[username]
	s.rmu.Unlock()

	if prefer {
		return preferOrder(ranked, cur, margin)
	}

	// 僅需排除一個已置首的綁定 ID，字串比較即可；去重 map 是純配置浪費。
	out := make([]tunnel.Tunnel, 0, len(ranked)+1)
	head := ""
	if t, ok := s.registry.Bound(boundID); ok && s.registry.IsHealthy(boundID) {
		out = append(out, t)
		head = boundID
	}
	for _, r := range ranked {
		if r.Tunnel.ID() != head {
			out = append(out, r.Tunnel)
		}
	}
	return out
}

// preferOrder 全域模式候選序：首位＝黏住出口（健康時），不通才改選飄移目標；
// margin > 0 時，最快者比黏住出口快超過容差才換黏（雙方延遲均需已知）。
func preferOrder(ranked []tunnel.Ranked, cur string, margin time.Duration) []tunnel.Tunnel {
	if len(ranked) == 0 {
		return nil
	}
	// 單次掃描同時定位黏住出口與飄移目標（延遲已知的最低者，
	// 抑制重建後歸零的隧道搶首位）；延遲已在清單內，無需回查註冊表。
	head, drift := -1, -1
	for i := range ranked {
		if head < 0 && cur != "" && ranked[i].Tunnel.ID() == cur {
			head = i
		}
		if drift < 0 && ranked[i].Latency > 0 {
			drift = i
		}
		if head >= 0 && drift >= 0 {
			break
		}
	}
	if drift < 0 { // 全清單皆無讀數：退回延遲排序首位
		drift = 0
	}
	switch {
	case head < 0: // 黏住出口不通（或尚未黏住）：改選飄移目標
		head = drift
	case margin > 0 && drift != head: // margin = 0 永不因延遲換黏
		cl, bl := ranked[head].Latency, ranked[drift].Latency
		if cl > 0 && bl > 0 && cl-bl > margin {
			head = drift
		}
	}
	out := make([]tunnel.Tunnel, 0, len(ranked))
	out = append(out, ranked[head].Tunnel)
	for i := range ranked {
		if i != head {
			out = append(out, ranked[i].Tunnel)
		}
	}
	return out
}
