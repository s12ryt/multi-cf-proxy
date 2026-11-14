// Package tunnel 的健康探測實作。
// 本檔功能定位：
//   - 行 20-32：探測站清單（三站獨立、IP 字面值）與測試注入點
//   - 行 40-60：DefaultProbe — 一輪全敗則等待後重試一次
//   - 行 62-95：probeRound — 三站並發、任一成功即判通、延遲取最小
//   - 行 97-130：probeSite / probeGet — 單站冷+穩態雙請求計時
package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// dohQuery RFC 8484 附錄 A 的 base64url 查詢（example.com A）。
// DoH wireformat GET 回 200 且無重定向，不觸發任何域名解析。
const dohQuery = "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

// probeTargets 三個互相獨立的探測站（Cloudflare / Google / Quad9）。
// 全為 IP 字面值：域名目標會在每輪探測經隧道 DNS，污染延遲量測並引入排序抖動。
// 三站並發、任一成功即判「通」——單一營運商故障或限流不應判隧道不可用。
// var（非 const slice）：測試以 httptest 覆蓋。
var probeTargets = []string{
	"https://1.1.1.1/cdn-cgi/trace",
	"https://8.8.8.8/dns-query?dns=" + dohQuery,
	"https://9.9.9.9/dns-query?dns=" + dohQuery,
}

// probeTLSConfig 僅測試注入（httptest 自簽證書需 InsecureSkipVerify）；正式路徑恆為 nil。
var probeTLSConfig *tls.Config

// probeRetryDelay 全站失敗後的重試等待。5s 探測間隔下，單次瞬時抖動
// （anycast 重路由／對端限流）若直接判不通會引發無謂飄移。
var probeRetryDelay = 500 * time.Millisecond

// minRoundBudget 單輪探測的最低時間；預算過小時寧可讓重試輪壓縮，
// 也不讓第一輪連握手都來不及。
const minRoundBudget = 500 * time.Millisecond

// errAllSitesDown 全部探測站皆失敗。
var errAllSitesDown = errors.New("全部探測站不可達")

// DefaultProbe 經隧道驗證數據路徑並量測穩態延遲。
// 一輪 = 三站並發；全敗則等 probeRetryDelay 後整輪重試一次，仍全敗才判不通。
func DefaultProbe(ctx context.Context, d Dialer) (time.Duration, error) {
	first, cancel := firstRoundContext(ctx)
	lat, err := probeRound(first, d)
	cancel()
	if err == nil {
		return lat, nil
	}
	select {
	case <-ctx.Done():
		return 0, err
	case <-time.After(probeRetryDelay):
	}
	return probeRound(ctx, d)
}

// firstRoundContext 把第一輪限制在「剩餘預算扣掉重試等待後的一半」。
// 共用外層 ctx 會讓第一輪吃光預算、重試輪秒敗（重試形同無效）。
func firstRoundContext(ctx context.Context) (context.Context, context.CancelFunc) {
	dl, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	budget := (time.Until(dl) - probeRetryDelay) / 2
	if budget < minRoundBudget {
		budget = minRoundBudget
	}
	return context.WithTimeout(ctx, budget)
}

// probeRound 並發探測全部站點：任一成功即判通，延遲取成功站中最小值
// （最小值代表路徑本身的能力，排除個別站的服務端開銷）。
func probeRound(ctx context.Context, d Dialer) (time.Duration, error) {
	type result struct {
		lat time.Duration
		err error
	}
	out := make(chan result, len(probeTargets))
	for _, target := range probeTargets {
		go func(u string) {
			lat, err := probeSite(ctx, d, u)
			out <- result{lat, err}
		}(target)
	}

	best, ok := time.Duration(0), false
	var firstErr error
	for range probeTargets {
		r := <-out
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		if !ok || r.lat < best {
			best, ok = r.lat, true
		}
	}
	if !ok {
		if firstErr == nil {
			firstErr = errAllSitesDown
		}
		return 0, fmt.Errorf("%w: %v", errAllSitesDown, firstErr)
	}
	return best, nil
}

// probeSite 單站兩個請求（同一 Transport，keep-alive 復用）：
//   - 冷請求走完整路徑（TCP+TLS+HTTP）驗證可達，不計時——冷 HTTPS ≈ 3×RTT
//     是握手結構的數學必然，不應反映為「延遲」。
//   - 穩態請求復用連線（≈1×RTT）計時，貼近真實瀏覽體驗。
func probeSite(ctx context.Context, d Dialer, url string) (time.Duration, error) {
	transport := &http.Transport{
		DialContext:           d.DialContext,
		MaxIdleConnsPerHost:   1,
		TLSClientConfig:       probeTLSConfig,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
	}
	// 單站上限恆小於總預算之半：否則一個慢站就能吃光預算，讓重試輪無機會執行。
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	defer transport.CloseIdleConnections() // 每輪自清：不跨輪持久化探測連線

	if err := probeGet(ctx, client, url); err != nil {
		return 0, err
	}
	start := time.Now()
	if err := probeGet(ctx, client, url); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// probeGet 發出單個請求並驗證回應；body 讀盡以允許連線復用。
func probeGet(ctx context.Context, c *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message, text/plain")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s 返回 HTTP %d", url, resp.StatusCode)
	}
	return nil
}
