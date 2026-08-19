// 多開CF代理（multi-cf-proxy）：在 VPS 上自管多條 Cloudflare WARP 隧道，
// 對外提供 SOCKS5 / HTTP 入站代理（帳密綁定不同 WARP 出口）與 Web 管理界面。
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/dispatcher"
	"multi-cf-proxy/internal/inbound"
	"multi-cf-proxy/internal/listen"
	"multi-cf-proxy/internal/stats"
	"multi-cf-proxy/internal/tunnel"
	"multi-cf-proxy/internal/warp"
	"multi-cf-proxy/internal/web"
)

// runtimeSnap 運行時套用器的差異快照（全部可比較欄位）。
type runtimeSnap struct {
	interval  int
	threshold int
	discard   float64
	probe     int
	dns       int
	prefer    bool
	socks     string
	httpA     string
	webA      string
}

// healthKey 健康類四項的比較鍵。
type healthKey struct {
	interval  int
	threshold int
	discard   float64
	probe     int
}

func (s runtimeSnap) health() healthKey {
	return healthKey{s.interval, s.threshold, s.discard, s.probe}
}

func main() {
	configPath := flag.String("config", "config.json", "配置文件路徑")
	flag.Parse()

	log.SetFlags(log.LstdFlags)

	cfg, err := config.NewManager(*configPath)
	if err != nil {
		log.Fatalf("載入配置失敗: %v", err)
	}
	if cfg.EnsureAdminPassword() {
		log.Printf("=== 已生成隨機管理員密碼: %s ===（保存在 %s，可登入 Web 後修改）", cfg.Get().AdminPassword, *configPath)
	}

	c := cfg.Get()
	tm := tunnel.NewManager(tunnel.WireFactory, tunnel.DefaultProbe,
		time.Duration(c.HealthCheck.IntervalSeconds)*time.Second,
		c.HealthCheck.FailureThreshold)
	tm.SetLatencyMax(time.Duration(c.HealthCheck.LatencyDiscardSeconds * float64(time.Second)))
	// 經隧道 DNS 結果本機快取（0 = 停用）；>0 時同域名連線免重複 DNS 往返
	if err := tm.SetDNSCacheTTL(time.Duration(c.DNSCacheSeconds) * time.Second); err != nil {
		log.Fatalf("設定 DNS 快取失敗: %v", err)
	}
	// 獨立延遲探測循環（0 = 隨健康檢查；>0 = 更高頻更新延遲並計入丟棄判定）
	if p := c.HealthCheck.LatencyProbeSeconds; p > 0 {
		tm.SetLatencyProbeInterval(time.Duration(p) * time.Second)
	}
	authStore := auth.NewStore(nil)
	collector := stats.NewCollector()
	svc := dispatcher.NewService(authStore, dispatcher.NewRegistry(tm), collector)
	svc.SetLatencyRouting(c.Routing.PreferLowestLatency)

	// 三個監聽服務（支持端口熱重載）
	ls := listen.New()
	if err := ls.Start("SOCKS5", c.ListenSocks5, func(ln net.Listener) error {
		return inbound.NewSOCKS5(svc).Serve(ln)
	}); err != nil {
		log.Fatal(err)
	}
	if err := ls.Start("HTTP", c.ListenHTTP, func(ln net.Listener) error {
		return inbound.NewHTTP(svc).Serve(ln)
	}); err != nil {
		log.Fatal(err)
	}

	webSrv := web.New(cfg, tm, authStore, collector, warp.NewClient().Register)
	webSrv.SetEgressSource(svc.EgressSnapshot)
	if err := ls.Start("Web", c.ListenWeb, func(ln net.Listener) error {
		return http.Serve(ln, webSrv.Handler())
	}); err != nil {
		log.Fatal(err)
	}

	// 冪等套用器：設置保存後按差異熱套運行時（health/dns/routing/端口）
	var snap atomic.Value
	snapOf := func(c *config.Config) runtimeSnap {
		return runtimeSnap{
			interval:  c.HealthCheck.IntervalSeconds,
			threshold: c.HealthCheck.FailureThreshold,
			discard:   c.HealthCheck.LatencyDiscardSeconds,
			probe:     c.HealthCheck.LatencyProbeSeconds,
			dns:       c.DNSCacheSeconds,
			prefer:    c.Routing.PreferLowestLatency,
			socks:     c.ListenSocks5,
			httpA:     c.ListenHTTP,
			webA:      c.ListenWeb,
		}
	}
	snap.Store(snapOf(c))
	webSrv.SetApplier(func(c *config.Config) []string {
		cur, _ := snap.Load().(runtimeSnap)
		next := snapOf(c)
		var notes []string
		if cur.health() != next.health() {
			tm.ApplyHealth(
				time.Duration(next.interval)*time.Second,
				next.threshold,
				time.Duration(next.discard*float64(time.Second)),
				time.Duration(next.probe)*time.Second,
			)
			notes = append(notes, "健康檢查/延遲參數已即時套用")
		}
		if cur.dns != next.dns {
			if err := tm.SetDNSCacheTTL(time.Duration(next.dns) * time.Second); err != nil {
				notes = append(notes, "DNS 快取套用失敗: "+err.Error())
			} else {
				notes = append(notes, "DNS 快取已即時套用")
			}
		}
		if cur.prefer != next.prefer {
			svc.SetLatencyRouting(next.prefer)
			notes = append(notes, "延遲優選已即時套用")
		}
		for _, sw := range []struct{ name, cur, next string }{
			{"SOCKS5", cur.socks, next.socks},
			{"HTTP", cur.httpA, next.httpA},
			{"Web", cur.webA, next.webA},
		} {
			if sw.cur != sw.next {
				if err := ls.Swap(sw.name, sw.next); err != nil {
					notes = append(notes, sw.name+" 端口套用失敗: "+err.Error())
				} else {
					notes = append(notes, sw.name+" 已切換到 "+sw.next)
				}
			}
		}
		snap.Store(next)
		return notes
	})

	if err := webSrv.SyncNow(context.Background()); err != nil {
		log.Printf("警告: 初始隧道同步失敗: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 健康巡檢循環
	go tm.Run(ctx)

	log.Printf("多開CF代理已啟動：SOCKS5=%s HTTP=%s Web=%s（上游 %d 個）",
		c.ListenSocks5, c.ListenHTTP, c.ListenWeb, len(c.Upstreams))

	errCh := ls.ErrCh()
	select {
	case <-ctx.Done():
		log.Println("收到退出信號，正在關閉…")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("監聽服務異常退出: %v", err)
		}
	}

	tm.StopAll()
	log.Println("已退出")
}
