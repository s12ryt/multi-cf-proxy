package dispatcher

import (
	"errors"

	"multi-cf-proxy/internal/tunnel"
)

var errProbe = errors.New("probe fail")

// tunnelManagerRegistry 把 tunnel.Manager 適配為 dispatcher.Registry。
type tunnelManagerRegistry struct {
	tm *tunnel.Manager
}

// NewRegistry 由 tunnel.Manager 構建 Registry。
func NewRegistry(tm *tunnel.Manager) Registry {
	return &tunnelManagerRegistry{tm: tm}
}

func (r *tunnelManagerRegistry) Bound(upstreamID string) (tunnel.Tunnel, bool) {
	return r.tm.Get(upstreamID)
}

// HealthyRanked 健康上游與其 EMA 平滑延遲（0 表示尚無讀數，含重建後歸零）。
func (r *tunnelManagerRegistry) HealthyRanked() []tunnel.Ranked {
	return r.tm.HealthyRanked()
}

func (r *tunnelManagerRegistry) IsHealthy(upstreamID string) bool {
	return r.tm.IsHealthy(upstreamID)
}
