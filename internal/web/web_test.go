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
	rebuilds atomic.Int64
}

func (f *fakeTunnel) ID() string                        { return f.id }
func (f *fakeTunnel) Fingerprint() string               { return "fp-" + f.id }
func (f *fakeTunnel) Start(ctx context.Context) error   { return nil }
func (f *fakeTunnel) Stop()                             {}
func (f *fakeTunnel) Rebuild(ctx context.Context) error { f.rebuilds.Add(1); return nil }
func (f *fakeTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("測試樁不撥號")
}

type testEnv struct {
	srv      *httptest.Server
	cfgPath  string
	cfg      *config.Manager
	tm       *tunnel.Manager
	tunnels  map[string]*fakeTunnel
	regCalls atomic.Int64
	regErr   atomic.Value // error
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
		tunnels[u.ID] = ft
		return ft, nil
	}
	tm := tunnel.NewManager(factory, func(ctx context.Context, d tunnel.Dialer) (time.Duration, error) {
		return 5 * time.Millisecond, nil
	}, 30*time.Second, 3)

	env := &testEnv{cfgPath: cfgPath, cfg: cfg, tm: tm, tunnels: tunnels}
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

	s := New(cfg, tm, auth.NewStore(nil), stats.NewCollector(), register)
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

	// 手動重建
	resp, _ = e.do(t, "POST", "/api/upstreams/"+id+"/rebuild", nil, &ck)
	if resp.StatusCode != 200 {
		t.Fatalf("重建應 200, got %d", resp.StatusCode)
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
