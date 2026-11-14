package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// withProbeTargets 覆蓋探測站清單與重試間隔（測試用，自動還原）。
func withProbeTargets(t *testing.T, urls ...string) {
	t.Helper()
	oldT, oldTLS, oldD := probeTargets, probeTLSConfig, probeRetryDelay
	probeTargets = urls
	probeTLSConfig = &tls.Config{InsecureSkipVerify: true} // 僅測試：信任 httptest 自簽證書
	probeRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { probeTargets, probeTLSConfig, probeRetryDelay = oldT, oldTLS, oldD })
}

// directDialer 直連 Transport 傳入的位址（繞過隧道，測試用）。
func directDialer() probeDialerFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", addr)
	}
}

// siteServer 起一台 TLS 測試站：statusFn 決定每次請求的狀態碼，delay 為穩態請求的服務延遲。
func siteServer(t *testing.T, hits *atomic.Int32, status func(n int32) int, coldDelay, warmDelay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n == 1 {
			time.Sleep(coldDelay)
		} else {
			time.Sleep(warmDelay)
		}
		if code := status(n); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		io.WriteString(w, "fl=web\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func always200(int32) int { return http.StatusOK }
func always500(int32) int { return http.StatusInternalServerError }

// hangServer 起一台永不回應的 TLS 測試站（請求阻塞至 ctx 取消）。
func hangServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestProbeRetryKeepsBudgetUnderDeadline A59：第一輪必須只花掉一半預算，
// 否則「全敗等 0.5s 再重試」會因共用 ctx 而秒敗，重試形同無效。
func TestProbeRetryKeepsBudgetUnderDeadline(t *testing.T) {
	var h1, h2 atomic.Int32
	s1, s2 := hangServer(t, &h1), hangServer(t, &h2)
	withProbeTargets(t, s1.URL, s2.URL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := DefaultProbe(ctx, directDialer()); err == nil {
		t.Fatal("全站無回應應判失敗")
	}
	for i, h := range []*atomic.Int32{&h1, &h2} {
		if got := h.Load(); got != 2 {
			t.Errorf("站 %d 命中 %d 次, want 2（第一輪 + 重試輪各一次）", i+1, got)
		}
	}
}

// TestProbeTargetsAreDistinctIPLiterals 三個互相獨立的探測站：IP 字面值（零 DNS 依賴）、主機互異。
func TestProbeTargetsAreDistinctIPLiterals(t *testing.T) {
	if len(probeTargets) != 3 {
		t.Fatalf("探測站數應為 3, got %d", len(probeTargets))
	}
	seen := map[string]bool{}
	for _, raw := range probeTargets {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("探測站 %q 無法解析: %v", raw, err)
		}
		if net.ParseIP(u.Hostname()) == nil {
			t.Errorf("探測站應為 IP 字面值（免隧道 DNS）, got %q", u.Hostname())
		}
		if !strings.HasPrefix(raw, "https://") {
			t.Errorf("探測站應走 TLS, got %q", raw)
		}
		if seen[u.Hostname()] {
			t.Errorf("探測站 %q 重複，失去獨立性", u.Hostname())
		}
		seen[u.Hostname()] = true
	}
}

// TestProbeAnySiteSuccessJudgesReachable 任一站成功即判「通」：單站故障不應讓隧道被判不通。
func TestProbeAnySiteSuccessJudgesReachable(t *testing.T) {
	var h1, h2, h3 atomic.Int32
	bad1 := siteServer(t, &h1, always500, 0, 0)
	bad2 := siteServer(t, &h2, always500, 0, 0)
	good := siteServer(t, &h3, always200, 0, 20*time.Millisecond)
	withProbeTargets(t, bad1.URL, bad2.URL, good.URL)

	lat, err := DefaultProbe(context.Background(), directDialer())
	if err != nil {
		t.Fatalf("單站成功應判通: %v", err)
	}
	if lat <= 0 {
		t.Errorf("應取成功站的穩態延遲, got %v", lat)
	}
}

// TestProbeTakesMinLatencyAcrossSites 延遲取成功站中最小值（避免慢站拖高排序讀數）。
func TestProbeTakesMinLatencyAcrossSites(t *testing.T) {
	var hs, hf atomic.Int32
	slow := siteServer(t, &hs, always200, 0, 200*time.Millisecond)
	fast := siteServer(t, &hf, always200, 0, 10*time.Millisecond)
	withProbeTargets(t, slow.URL, fast.URL)

	lat, err := DefaultProbe(context.Background(), directDialer())
	if err != nil {
		t.Fatalf("DefaultProbe: %v", err)
	}
	if lat >= 150*time.Millisecond {
		t.Errorf("應取最小延遲（≈10ms）, got %v", lat)
	}
}

// TestProbeMeasuresWarmSteadyStatePerSite 每站冷+穩態雙請求：冷路徑僅驗證不計時。
func TestProbeMeasuresWarmSteadyStatePerSite(t *testing.T) {
	var hits atomic.Int32
	srv := siteServer(t, &hits, always200, 150*time.Millisecond, 30*time.Millisecond)
	withProbeTargets(t, srv.URL)

	lat, err := DefaultProbe(context.Background(), directDialer())
	if err != nil {
		t.Fatalf("DefaultProbe: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("每站應發出冷+穩態兩個請求, got %d", got)
	}
	if lat < 15*time.Millisecond {
		t.Errorf("量測應涵蓋穩態請求的服務延遲（≈30ms）, got %v", lat)
	}
	if lat >= 100*time.Millisecond {
		t.Errorf("量測不應包含冷啟動 150ms, got %v", lat)
	}
}

// TestProbeRetriesOnceWhenAllSitesFail 三站全敗 → 等待後整輪重試一次；仍全敗才回報不通。
func TestProbeRetriesOnceWhenAllSitesFail(t *testing.T) {
	var h1, h2 atomic.Int32
	s1 := siteServer(t, &h1, always500, 0, 0)
	s2 := siteServer(t, &h2, always500, 0, 0)
	withProbeTargets(t, s1.URL, s2.URL)

	if _, err := DefaultProbe(context.Background(), directDialer()); err == nil {
		t.Fatal("全站失敗應回報錯誤")
	}
	if got := h1.Load(); got != 2 {
		t.Errorf("站 1 應被探測兩輪（原輪+重試一次）, got %d", got)
	}
	if got := h2.Load(); got != 2 {
		t.Errorf("站 2 應被探測兩輪（原輪+重試一次）, got %d", got)
	}
}

// TestProbeRetrySucceedsAfterTransientFailure 首輪全敗、重試成功 → 不判不通（抑制瞬時抖動飄移）。
func TestProbeRetrySucceedsAfterTransientFailure(t *testing.T) {
	var hits atomic.Int32
	srv := siteServer(t, &hits, func(n int32) int {
		if n == 1 {
			return http.StatusInternalServerError
		}
		return http.StatusOK
	}, 0, 5*time.Millisecond)
	withProbeTargets(t, srv.URL)

	if _, err := DefaultProbe(context.Background(), directDialer()); err != nil {
		t.Fatalf("重試成功不應回報錯誤: %v", err)
	}
}
