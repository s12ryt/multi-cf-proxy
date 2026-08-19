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

func (r *tunnelManagerRegistry) LatencyOf(upstreamID string) (time.Duration, bool) {
	st, ok := r.tm.States()[upstreamID]
	if !ok || st.LastLatency == 0 {
		return 0, false
	}
	return st.LastLatency, true
}
