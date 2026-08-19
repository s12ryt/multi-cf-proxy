package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/stats"
	"multi-cf-proxy/internal/tunnel"
	"multi-cf-proxy/internal/warp"
)

const validConfText = `[Interface]
PrivateKey = yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=
Address = 172.16.0.9/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = engage.cloudflareclient.com:2408
`

// fakeTunnel web 測試用隧道樁。
type fakeTunnel struct {
	id       string
	fp       atomic.Value // 配置指紋（factory 時快照，避免 Sync 誤判重建）
	rebuilds atomic.Int64
}

func (f *fakeTunnel) ID() string { return f.id }
func (f *fakeTunnel) Fingerprint() string {
	if v, ok := f.fp.Load().(string); ok {
		return v
	}
	return ""
}
func (f *fakeTunnel) Start(ctx context.Context) error   { return nil }
func (f *fakeTunnel) Stop()                             {}
func (f *fakeTunnel) Rebuild(ctx context.Context) error { f.rebuilds.Add(1); return nil }
func (f *fakeTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("測試樁不撥號")
}

type testEnv struct {
	srv      *httptest.Server
	webSrv   *Server
	cfgPath  string
	cfg      *config.Manager
	tm       *tunnel.Manager
	tunnels  map[string]*fakeTunnel
	regCalls atomic.Int64
	regErr   atomic.Value // error
	st       *stats.Collector
	client   *http.Client
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	cfgPath := t.TempDir() + "/config.json"
	cfg, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.EnsureAdminPassword()

	tunnels := map[string]*fakeTunnel{}
	factory := func(u *config.Upstream) (tunnel.Tunnel, error) {
		ft := &fakeTunnel{id: u.ID}
		ft.fp.Store(u.PrivateKey + "|" + u.PeerPublicKey + "|" + u.Endpoint + "|" + fmt.Sprint(u.Addresses))
		tunnels[u.ID] = ft
		return ft, nil
	}
	tm := tunnel.NewManager(factory, func(ctx context.Context, d tunnel.Dialer) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	}, 30*time.Second, 3)

	env := &testEnv{cfgPath: cfgPath, cfg: cfg, tm: tm, tunnels: tunnels}
	env.st = stats.NewCollector()
	env.regCalls.Store(0)
	register := func(ctx context.Context) (warp.Conf, error) {
		n := env.regCalls.Add(1)
		if e, ok := env.regErr.Load().(error); ok && e != nil {
			return warp.Conf{}, e
		}
		return warp.Conf{
			PrivateKey:    base64Key(int(n)),
			PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
			Endpoint:      "engage.cloudflareclient.com:2408",
			Addresses:     []string{"172.16.0.2/32"},
		}, nil
	}

	s := New(cfg, tm, auth.NewStore(nil), env.st, register)
	env.webSrv = s
	env.srv = httptest.NewServer(s.Handler())
	t.Cleanup(env.srv.Close)

	env.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return env
}

func base64Key(n int) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(n + i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// SetApplier 注入設置套用器樁（轉發給 Server）。
func (e *testEnv) SetApplier(f func(c *config.Config) []string) {
	e.webSrv.SetApplier(f)
}

func (e *testEnv) adminPassword() string { return e.cfg.Get().AdminPassword }

func (e *testEnv) do(t *testing.T, method, path string, body any, cookie *string) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil && *cookie != "" {
		req.Header.Set("Cookie", "mcp_session="+*cookie)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(raw, &m)
	if c := resp.Header.Get("Set-Cookie"); strings.HasPrefix(c, "mcp_session=") {
		if cookie != nil {
			*cookie = strings.SplitN(strings.SplitN(c, "=", 2)[1], ";", 2)[0]
		}
	}
	return resp, m
}

func (e *testEnv) login(t *testing.T) string {
	t.Helper()
	cookie := ""
	resp, _ := e.do(t, "POST", "/api/login", map[string]string{"password": e.adminPassword()}, &cookie)
	if resp.StatusCode != 200 || cookie == "" {
		t.Fatalf("登入失敗: %d %q", resp.StatusCode, cookie)
	}
	return cookie
}

// ---- 測試 ----

func TestLoginFlow(t *testing.T) {
	e := newTestEnv(t)
	cookie := ""

	// 錯誤密碼
	resp, _ := e.do(t, "POST", "/api/login", map[string]string{"password": "wrong"}, &cookie)
	if resp.StatusCode != 401 {
		t.Errorf("錯密碼應 401, got %d", resp.StatusCode)
	}

	// 未登入存取受保護 API
	resp, _ = e.do(t, "GET", "/api/overview", nil, &cookie)
	if resp.StatusCode != 401 {
		t.Errorf("未登入應 401, got %d", resp.StatusCode)
	}

	// 正確密碼
	ck := e.login(t)
	if ck == "" {
		t.Fatal("應拿到 session cookie")
	}

	// 登入後可存取
	resp, m := e.do(t, "GET", "/api/overview", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("登入後 overview 應 200, got %d", resp.StatusCode)
	}
	if _, ok := m["upstreams"]; !ok {
		t.Errorf("overview 應含 upstreams: %v", m)
	}

	// 登出後原 session 失效
	resp, _ = e.do(t, "POST", "/api/logout", nil, &ck)
	if resp.StatusCode != 200 {
		t.Errorf("登出應 200, got %d", resp.StatusCode)
	}
	resp, _ = e.do(t, "GET", "/api/overview", nil, &ck)
	if resp.StatusCode != 401 {
		t.Errorf("登出後應 401, got %d", resp.StatusCode)
	}
}

func TestAutoRegister(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)

	resp, m := e.do(t, "POST", "/api/upstreams/auto", map[string]int{"count": 2}, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("auto 註冊應 200, got %d: %v", resp.StatusCode, m)
	}
	if e.regCalls.Load() != 2 {
		t.Errorf("註冊調用次數 = %d", e.regCalls.Load())
	}
	ups := e.cfg.Get().Upstreams
	if len(ups) != 2 {
		t.Fatalf("配置應有 2 個上游: %d", len(ups))
	}
	if ups[0].Account.Username == ups[1].Account.Username || ups[0].Account.Password == ups[1].Account.Password {
		t.Error("兩個上游應有不同隨機帳密")
	}
	if !ups[0].Enabled {
		t.Error("新上游應默認啟用")
	}
	// 隧道應已同步
	if len(e.tunnels) != 2 {
		t.Errorf("隧道應同步建立: %v", e.tunnels)
	}
}

func TestAutoRegisterAPIFailure(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	e.regErr.Store(fmt.Errorf("CF 風控"))

	resp, _ := e.do(t, "POST", "/api/upstreams/auto", map[string]int{"count": 1}, &ck)
	if resp.StatusCode != 502 {
		t.Fatalf("註冊失敗應 502, got %d", resp.StatusCode)
	}
	if len(e.cfg.Get().Upstreams) != 0 {
		t.Error("失敗時不應寫入半成品上游")
	}
}

func TestImportConf(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)

	resp, m := e.do(t, "POST", "/api/upstreams/import", map[string]string{"conf": validConfText, "name": "手動導入一號"}, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("import 應 200, got %d: %v", resp.StatusCode, m)
	}
	ups := e.cfg.Get().Upstreams
	if len(ups) != 1 || ups[0].Name != "手動導入一號" {
		t.Fatalf("配置應有命名上游: %+v", ups)
	}
	if ups[0].Account.Username == "" || len(ups[0].Account.Password) < 8 {
		t.Errorf("導入上游應自動分配帳密: %+v", ups[0].Account)
	}

	// 重複導入相同 conf → 允許（多帳號各自帳密）
	resp, _ = e.do(t, "POST", "/api/upstreams/import", map[string]string{"conf": validConfText}, &ck)
	if resp.StatusCode != 200 {
		t.Errorf("第二次導入應 200, got %d", resp.StatusCode)
	}
}

func TestImportInvalidConf(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	resp, _ := e.do(t, "POST", "/api/upstreams/import", map[string]string{"conf": "not a conf"}, &ck)
	if resp.StatusCode != 400 {
		t.Errorf("非法 conf 應 400, got %d", resp.StatusCode)
	}
}

// TestUpstreamCredentialsEndpoint 按需取憑證（複製連結用）：
// 需 session；返回該上游帳密；不存在 404；未登入 401。
func TestUpstreamCredentialsEndpoint(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	e.do(t, "POST", "/api/upstreams/auto", map[string]int{"count": 1}, &ck)
	id := e.cfg.Get().Upstreams[0].ID
	wantUser := e.cfg.Get().Upstreams[0].Account.Username
	wantPass := e.cfg.Get().Upstreams[0].Account.Password

	// 未登入 401
	empty := ""
	resp, _ := e.do(t, "GET", "/api/upstreams/"+id+"/credentials", nil, &empty)
	if resp.StatusCode != 401 {
		t.Fatalf("未登入應 401, got %d", resp.StatusCode)
	}

	// 正常返回帳密
	resp, m := e.do(t, "GET", "/api/upstreams/"+id+"/credentials", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("應 200, got %d", resp.StatusCode)
	}
	if m["username"] != wantUser || m["password"] != wantPass {
		t.Errorf("帳密不一致: %v", m)
	}

	// 不存在 404
	resp, _ = e.do(t, "GET", "/api/upstreams/nope/credentials", nil, &ck)
	if resp.StatusCode != 404 {
		t.Errorf("不存在應 404, got %d", resp.StatusCode)
	}
}

func TestUpstreamLifecycle(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	e.do(t, "POST", "/api/upstreams/auto", map[string]int{"count": 1}, &ck)
	id := e.cfg.Get().Upstreams[0].ID
	oldPass := e.cfg.Get().Upstreams[0].Account.Password

	// 停用
	resp, _ := e.do(t, "PATCH", "/api/upstreams/"+id, map[string]bool{"enabled": false}, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("停用應 200, got %d", resp.StatusCode)
	}
	if e.cfg.Get().Upstreams[0].Enabled {
		t.Error("應已停用")
	}

	// 手動重建（v1.6 語意：停用上游不可重建——400，且不觸碰隧道）
	resp, _ = e.do(t, "POST", "/api/upstreams/"+id+"/rebuild", nil, &ck)
	if resp.StatusCode != 400 {
		t.Fatalf("停用上游重建應 400, got %d", resp.StatusCode)
	}
	if e.tunnels[id].rebuilds.Load() != 0 {
		t.Error("停用上游不應被重建")
	}

	// 重新啟用後重建 → 200
	resp, _ = e.do(t, "PATCH", "/api/upstreams/"+id, map[string]bool{"enabled": true}, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("重新啟用應 200, got %d", resp.StatusCode)
	}
	resp, _ = e.do(t, "POST", "/api/upstreams/"+id+"/rebuild", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("啟用上游重建應 200, got %d", resp.StatusCode)
	}
	if e.tunnels[id].rebuilds.Load() < 1 {
		t.Error("隧道應被重建")
	}

	// 重生成帳密
	resp, _ = e.do(t, "POST", "/api/upstreams/"+id+"/credentials", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("重生成應 200, got %d", resp.StatusCode)
	}
	np := e.cfg.Get().Upstreams[0].Account.Password
	if np == oldPass || len(np) < 8 {
		t.Errorf("新密碼應不同且合格: %q", np)
	}

	// 刪除
	resp, _ = e.do(t, "DELETE", "/api/upstreams/"+id, nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("刪除應 200, got %d", resp.StatusCode)
	}
	if len(e.cfg.Get().Upstreams) != 0 {
		t.Error("應已刪除")
	}
}

func TestSettingsUpdate(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)

	body := map[string]any{
		"listen_socks5": ":2080",
		"listen_http":   ":8080",
		"listen_web":    ":8081",
		"health": map[string]any{
			"interval_seconds":        60,
			"failure_threshold":       2,
			"latency_discard_seconds": 1.5,
		},
	}
	resp, _ := e.do(t, "PUT", "/api/settings", body, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("settings 應 200, got %d", resp.StatusCode)
	}
	c := e.cfg.Get()
	if c.ListenSocks5 != ":2080" || c.HealthCheck.IntervalSeconds != 60 || c.HealthCheck.LatencyDiscardSeconds != 1.5 {
		t.Errorf("設置未持久化: %+v", c)
	}

	// 舊版/部分客戶端只更新既有健康欄位時，不可默默清除新門檻。
	partial := map[string]any{"health": map[string]int{"interval_seconds": 45}}
	resp, _ = e.do(t, "PUT", "/api/settings", partial, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("部分健康設置應 200, got %d", resp.StatusCode)
	}
	if got := e.cfg.Get().HealthCheck.LatencyDiscardSeconds; got != 1.5 {
		t.Errorf("省略欄位不應重置延遲門檻: got %v, want 1.5", got)
	}

	// 非法端口
	bad := map[string]any{"listen_socks5": "bad"}
	resp, _ = e.do(t, "PUT", "/api/settings", bad, &ck)
	if resp.StatusCode != 400 {
		t.Errorf("非法設置應 400, got %d", resp.StatusCode)
	}

	// 負的延遲丟棄門檻非法。
	bad = map[string]any{"health": map[string]any{"latency_discard_seconds": -0.1}}
	resp, _ = e.do(t, "PUT", "/api/settings", bad, &ck)
	if resp.StatusCode != 400 {
		t.Errorf("負的延遲門檻應 400, got %d", resp.StatusCode)
	}

	// v1.6：DNS 快取與延遲探測設置——保存、部分更新保持、負值拒絕。
	full := map[string]any{
		"dns_cache_seconds": 120,
		"health":            map[string]any{"latency_probe_seconds": 5},
	}
	if resp, _ = e.do(t, "PUT", "/api/settings", full, &ck); resp.StatusCode != 200 {
		t.Fatalf("DNS/探測設置應 200, got %d", resp.StatusCode)
	}
	got := e.cfg.Get()
	if got.DNSCacheSeconds != 120 || got.HealthCheck.LatencyProbeSeconds != 5 {
		t.Errorf("DNS/探測設置未生效: dns=%d probe=%d", got.DNSCacheSeconds, got.HealthCheck.LatencyProbeSeconds)
	}
	// 僅更新端口：兩個新欄位不被重置
	if resp, _ = e.do(t, "PUT", "/api/settings", map[string]any{"listen_web": ":9090"}, &ck); resp.StatusCode != 200 {
		t.Fatalf("部分更新應 200")
	}
	got = e.cfg.Get()
	if got.DNSCacheSeconds != 120 || got.HealthCheck.LatencyProbeSeconds != 5 {
		t.Errorf("省略欄位不應重置: dns=%d probe=%d", got.DNSCacheSeconds, got.HealthCheck.LatencyProbeSeconds)
	}
	// 負值拒絕
	if resp, _ = e.do(t, "PUT", "/api/settings", map[string]any{"dns_cache_seconds": -1}, &ck); resp.StatusCode != 400 {
		t.Errorf("負 DNS 快取應 400, got %d", resp.StatusCode)
	}
	if resp, _ = e.do(t, "PUT", "/api/settings", map[string]any{"health": map[string]any{"latency_probe_seconds": -2}}, &ck); resp.StatusCode != 400 {
		t.Errorf("負探測間隔應 400, got %d", resp.StatusCode)
	}
	// overview 暴露 dns_cache_seconds
	resp, body = e.do(t, "GET", "/api/overview", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("overview 應 200")
	}
	s, _ := body["settings"].(map[string]any)
	if v, _ := s["dns_cache_seconds"].(float64); v != 120 {
		t.Errorf("overview settings.dns_cache_seconds = %#v, want 120", s["dns_cache_seconds"])
	}
	h, _ := s["health"].(map[string]any)
	if v, _ := h["latency_probe_seconds"].(float64); v != 5 {
		t.Errorf("overview settings.health.latency_probe_seconds = %#v, want 5", h["latency_probe_seconds"])
	}
}

func TestOverviewIncludesLastLatency(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	resp, _ := e.do(t, "POST", "/api/upstreams/import", map[string]string{"conf": validConfText}, &ck)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("導入應成功: %d", resp.StatusCode)
	}
	id := e.cfg.Get().Upstreams[0].ID
	e.tm.RecordProbe(id, nil, 123*time.Millisecond)

	resp, body := e.do(t, "GET", "/api/overview", nil, &ck)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview 應成功: %d", resp.StatusCode)
	}
	ups, ok := body["upstreams"].([]any)
	if !ok || len(ups) != 1 {
		t.Fatalf("overview upstreams 格式錯誤: %#v", body["upstreams"])
	}
	up := ups[0].(map[string]any)
	if got, ok := up["last_latency_ms"].(float64); !ok || got != 123 {
		t.Errorf("last_latency_ms = %#v, want 123", up["last_latency_ms"])
	}
}

func TestChangeAdminPassword(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)

	resp, _ := e.do(t, "PUT", "/api/admin/password", map[string]string{"password": "new-password-123"}, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("改密碼應 200, got %d", resp.StatusCode)
	}
	if e.adminPassword() != "new-password-123" {
		t.Error("密碼未更新")
	}
	// 舊 session 仍有效但需用新密碼登入
	cookie := ""
	resp, _ = e.do(t, "POST", "/api/login", map[string]string{"password": "new-password-123"}, &cookie)
	if resp.StatusCode != 200 {
		t.Errorf("新密碼應可登入, got %d", resp.StatusCode)
	}
}

func TestStatsEndpoint(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	e.cfg.Update(func(c *config.Config) error {
		c.Upstreams = append(c.Upstreams, config.Upstream{
			ID: "u1", Name: "n", Enabled: true,
			PrivateKey: "k", PeerPublicKey: "p", Endpoint: "e:1",
			Addresses: []string{"172.16.0.2/32"},
			Account:   config.Account{Username: "warp-aaaa", Password: "pw1"},
		})
		return nil
	})
	// 觸發 sync（overview 也會）
	e.do(t, "GET", "/api/overview", nil, &ck)

	resp, m := e.do(t, "GET", "/api/stats", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("stats 應 200, got %d", resp.StatusCode)
	}
	if _, ok := m["accounts"]; !ok {
		t.Errorf("stats 應含 accounts: %v", m)
	}
}

// TestStatsIncludesDial v1.6：stats API 應含撥號延遲分佈（count/p50/p95/max）。
func TestStatsIncludesDial(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	for i := 1; i <= 20; i++ {
		e.st.RecordDial(time.Duration(i) * time.Millisecond)
	}

	resp, m := e.do(t, "GET", "/api/stats", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("stats 應 200, got %d", resp.StatusCode)
	}
	dial, ok := m["dial"].(map[string]any)
	if !ok {
		t.Fatalf("stats 應含 dial 物件: %v", m)
	}
	if dial["count"].(float64) != 20 {
		t.Errorf("dial.count = %v, want 20", dial["count"])
	}
	// 20 筆 1..20ms：nearest-rank p50=10ms、p95=19ms、max=20ms
	if dial["p50_ms"].(float64) != 10 {
		t.Errorf("dial.p50_ms = %v, want 10", dial["p50_ms"])
	}
	if dial["p95_ms"].(float64) != 19 {
		t.Errorf("dial.p95_ms = %v, want 19", dial["p95_ms"])
	}
	if dial["max_ms"].(float64) != 20 {
		t.Errorf("dial.max_ms = %v, want 20", dial["max_ms"])
	}
}

// TestRebuildEndpointSemantics v1.6：重建按鈕走狀態機——停用上游 400、不存在 404、成功 200 且計數。
func TestRebuildEndpointSemantics(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)
	mk := func(id string, enabled bool) {
		e.cfg.Update(func(c *config.Config) error {
			c.Upstreams = append(c.Upstreams, config.Upstream{
				ID: id, Name: id, Enabled: enabled,
				PrivateKey: base64Key(1), PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
				Endpoint: "engage.cloudflareclient.com:2408", Addresses: []string{"172.16.0.2/32"},
				Account: config.Account{Username: "u-" + id, Password: "pw-" + id},
			})
			return nil
		})
	}
	mk("uon", true)
	mk("uoff", false)
	// 直接對齊隧道集合（overview 不觸發 sync）
	c := e.cfg.Get()
	ups := make([]*config.Upstream, 0, len(c.Upstreams))
	for i := range c.Upstreams {
		ups = append(ups, &c.Upstreams[i])
	}
	if err := e.tm.Sync(context.Background(), ups); err != nil {
		t.Fatal(err)
	}

	// 停用上游 → 400（不可喚醒未運行隧道）
	resp, _ := e.do(t, "POST", "/api/upstreams/uoff/rebuild", nil, &ck)
	if resp.StatusCode != 400 {
		t.Errorf("停用上游重建應 400, got %d", resp.StatusCode)
	}
	if e.tunnels["uoff"].rebuilds.Load() != 0 {
		t.Error("停用上游不應被重建")
	}

	// 不存在 → 404
	resp, _ = e.do(t, "POST", "/api/upstreams/nope/rebuild", nil, &ck)
	if resp.StatusCode != 404 {
		t.Errorf("不存在上游應 404, got %d", resp.StatusCode)
	}

	// 啟用上游 → 200，底層重建計數 +1
	resp, _ = e.do(t, "POST", "/api/upstreams/uon/rebuild", nil, &ck)
	if resp.StatusCode != 200 {
		t.Errorf("啟用上游重建應 200, got %d", resp.StatusCode)
	}
	if e.tunnels["uon"].rebuilds.Load() < 1 {
		t.Error("啟用上游應被重建")
	}
}

func TestSettingsRoutingAndApplier(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)

	var appliedCount atomic.Int64
	var appliedCfg *config.Config
	e.SetApplier(func(c *config.Config) []string {
		appliedCfg = c
		appliedCount.Add(1)
		return []string{"測試報告"}
	})

	// routing 設置保存 + applier 觸發
	body := map[string]any{
		"routing": map[string]any{"prefer_lowest_latency": true},
	}
	resp, jbody := e.do(t, "PUT", "/api/settings", body, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("routing 設置應 200, got %d", resp.StatusCode)
	}
	if appliedCount.Load() != 1 {
		t.Errorf("applier 應被調用一次, got %d", appliedCount.Load())
	}
	if appliedCfg == nil || !appliedCfg.Routing.PreferLowestLatency {
		t.Errorf("applier 應收到保存後的新配置: %+v", appliedCfg)
	}
	if note, _ := jbody["note"].(string); strings.Contains(note, "重啟") {
		t.Errorf("回應不應再提示重啟: %q", note)
	}
	applied, _ := jbody["applied"].([]any)
	if len(applied) != 1 {
		t.Errorf("回應 applied 應包含套用報告, got %#v", jbody["applied"])
	}

	// overview 暴露 routing
	resp, jbody = e.do(t, "GET", "/api/overview", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("overview 應 200")
	}
	s, _ := jbody["settings"].(map[string]any)
	rt, _ := s["routing"].(map[string]any)
	if v, _ := rt["prefer_lowest_latency"].(bool); !v {
		t.Errorf("overview routing.prefer_lowest_latency = %#v, want true", rt["prefer_lowest_latency"])
	}
	if _, has := rt["switch_margin_ms"]; has {
		t.Error("overview 不應再暴露已移除的 switch_margin_ms")
	}
}

func TestRebuildResponseAndEgress(t *testing.T) {
	e := newTestEnv(t)
	ck := e.login(t)

	// 導入一個上游供重建
	resp, body := e.do(t, "POST", "/api/upstreams/import", map[string]string{"conf": validConfText, "name": "warp-t"}, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("導入應 200, got %d", resp.StatusCode)
	}
	id, _ := body["id"].(string)

	// 重建回應含 rebuilds 計數
	resp, body = e.do(t, "POST", "/api/upstreams/"+id+"/rebuild", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("重建應 200, got %d", resp.StatusCode)
	}
	if n, ok := body["rebuilds"].(float64); !ok || n < 1 {
		t.Errorf("重建回應應含 rebuilds>=1, got %#v", body["rebuilds"])
	}

	// overview：無 egress 來源時帳號 egress 回退綁定值
	resp, body = e.do(t, "GET", "/api/overview", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("overview 應 200")
	}
	accts, _ := body["accounts"].([]any)
	if len(accts) == 0 {
		t.Fatal("應至少一個帳號")
	}
	a0, _ := accts[0].(map[string]any)
	eg, _ := a0["egress"].(string)
	if eg == "" {
		t.Errorf("egress 應回退綁定上游 ID, got %#v", a0["egress"])
	}

	// 注入 egress 來源：顯示實際出口
	bound := eg
	e.webSrv.SetEgressSource(func() map[string]string {
		user, _ := a0["username"].(string)
		return map[string]string{user: "u-other"}
	})
	resp, body = e.do(t, "GET", "/api/overview", nil, &ck)
	accts, _ = body["accounts"].([]any)
	a0, _ = accts[0].(map[string]any)
	if eg, _ = a0["egress"].(string); eg != "u-other" || eg == bound {
		t.Errorf("egress 應為來源提供的實際出口 u-other, got %q", eg)
	}

	// State 快照暴露 rebuilding（重建完成後應為 false）
	ups, _ := body["upstreams"].([]any)
	u0, _ := ups[0].(map[string]any)
	if v, _ := u0["rebuilding"].(bool); v {
		t.Error("非重建期間 rebuilding 應為 false")
	}
}

// TestRebuildSurvivesClientDisconnect 手動重建不得因客戶端斷線而中止：
// handleRebuild 必須以獨立背景 ctx 執行（源碼契約：不得引用 r.Context()）。
// WireGuard 重建含握手可能達秒級；若綁架於請求 ctx，代理/瀏覽器逾時即中斷重建。
func TestRebuildSurvivesClientDisconnect(t *testing.T) {
	src, err := os.ReadFile("web.go")
	if err != nil {
		t.Fatalf("讀取 web.go 失敗: %v", err)
	}
	text := string(src)
	start := strings.Index(text, "func (s *Server) handleRebuild")
	if start < 0 {
		t.Fatal("找不到 handleRebuild")
	}
	body := text[start:]
	if end := strings.Index(body[1:], "\nfunc "); end >= 0 {
		body = body[:end+1]
	}
	if strings.Contains(body, "r.Context()") {
		t.Error("handleRebuild 不得使用 r.Context()（客戶端斷線會中止進行中的重建）；請改用帶逾時的背景 ctx")
	}
	if !strings.Contains(body, "context.WithTimeout(context.Background()") {
		t.Error("handleRebuild 應以帶逾時的背景 ctx 執行重建")
	}
}
