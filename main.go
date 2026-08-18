// 多開CF代理（multi-cf-proxy）：在 VPS 上自管多條 Cloudflare WARP 隧道，
// 對外提供 SOCKS5 / HTTP 入站代理（帳密綁定不同 WARP 出口）與 Web 管理界面。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/dispatcher"
	"multi-cf-proxy/internal/inbound"
	"multi-cf-proxy/internal/stats"
	"multi-cf-proxy/internal/tunnel"
	"multi-cf-proxy/internal/warp"
	"multi-cf-proxy/internal/web"
)

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
	authStore := auth.NewStore(nil)
	collector := stats.NewCollector()
	svc := dispatcher.NewService(authStore, dispatcher.NewRegistry(tm), collector)

	webSrv := web.New(cfg, tm, authStore, collector, warp.NewClient().Register)
	if err := webSrv.SyncNow(context.Background()); err != nil {
		log.Printf("警告: 初始隧道同步失敗: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 健康巡檢循環
	go tm.Run(ctx)

	// 三個監聽服務
	errCh := make(chan error, 3)
	startListener("SOCKS5", c.ListenSocks5, func(ln net.Listener) error {
		return inbound.NewSOCKS5(svc).Serve(ln)
	}, errCh)
	startListener("HTTP", c.ListenHTTP, func(ln net.Listener) error {
		return inbound.NewHTTP(svc).Serve(ln)
	}, errCh)
	startListener("Web", c.ListenWeb, func(ln net.Listener) error {
		return http.Serve(ln, webSrv.Handler())
	}, errCh)

	log.Printf("多開CF代理已啟動：SOCKS5=%s HTTP=%s Web=%s（上游 %d 個）",
		c.ListenSocks5, c.ListenHTTP, c.ListenWeb, len(c.Upstreams))

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

// startListener 啟動一個 TCP 監聽；失敗直接終止進程。
func startListener(name, addr string, serve func(net.Listener) error, errCh chan error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("監聽 %s（%s）失敗: %v", name, addr, err)
	}
	go func() {
		if err := serve(ln); err != nil {
			errCh <- fmt.Errorf("%s: %w", name, err)
		}
	}()
}
