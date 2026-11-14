package dispatcher

import (
	"errors"
	"time"

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

func (r *tunnelManagerRegistry) Healthy() []tunnel.Tunnel {
	return r.tm.Healthy()
}

func (r *tunnelManagerRegistry) HealthySortedByLatency() []tunnel.Tunnel {
	return r.tm.HealthySortedByLatency()
}

func (r *tunnelManagerRegistry) IsHealthy(upstreamID string) bool {
	st, ok := r.tm.States()[upstreamID]
	return ok && st.Healthy && st.Running
}

// Latency 返回 EMA 平滑延遲；0 表示尚無讀數（含重建後歸零）。
func (r *tunnelManagerRegistry) Latency(upstreamID string) time.Duration {
	return r.tm.States()[upstreamID].LastLatency
}
