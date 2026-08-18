// Package web 提供管理界面：REST API（session 認證）與嵌入式前端單頁。
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/stats"
	"multi-cf-proxy/internal/tunnel"
	"multi-cf-proxy/internal/warp"
	"multi-cf-proxy/web"
)

const sessionCookie = "mcp_session"
const sessionTTL = 12 * time.Hour

// Server 管理界面服務器。
type Server struct {
	cfg       *config.Manager
	tm        *tunnel.Manager
	authStore *auth.Store
	stats     *stats.Collector
	register  func(ctx context.Context) (warp.Conf, error)

	mu       sync.Mutex
	sessions map[string]time.Time
}

// New 建立服務器。register 為 WARP 自動註冊函數（可注入測試樁）。
func New(cfg *config.Manager, tm *tunnel.Manager, authStore *auth.Store, st *stats.Collector, register func(ctx context.Context) (warp.Conf, error)) *Server {
	if register == nil {
		client := warp.NewClient()
		register = client.Register
	}
	return &Server{
		cfg:       cfg,
		tm:        tm,
		authStore: authStore,
		stats:     st,
		register:  register,
		sessions:  map[string]time.Time{},
	}
}

// Handler 組裝路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/overview", s.requireAuth(s.handleOverview))
	mux.HandleFunc("GET /api/stats", s.requireAuth(s.handleStats))
	mux.HandleFunc("POST /api/upstreams/auto", s.requireAuth(s.handleAutoRegister))
	mux.HandleFunc("POST /api/upstreams/import", s.requireAuth(s.handleImport))
	mux.HandleFunc("PATCH /api/upstreams/{id}", s.requireAuth(s.handlePatchUpstream))
	mux.HandleFunc("GET /api/upstreams/{id}/credentials", s.requireAuth(s.handleGetCredentials))
	mux.HandleFunc("POST /api/upstreams/{id}/rebuild", s.requireAuth(s.handleRebuild))
	mux.HandleFunc("POST /api/upstreams/{id}/credentials", s.requireAuth(s.handleRegenCredentials))
	mux.HandleFunc("DELETE /api/upstreams/{id}", s.requireAuth(s.handleDeleteUpstream))
	mux.HandleFunc("PUT /api/settings", s.requireAuth(s.handleSettings))
	mux.HandleFunc("PUT /api/admin/password", s.requireAuth(s.handleChangePassword))

	// 前端靜態資源（embed）
	mux.Handle("GET /", http.FileServerFS(staticFS()))

	return mux
}

// staticFS 由 web/ 目錄 embed（見 web/embed.go）。
func staticFS() fs.FS { return web.Static }

// ---- session ----

func (s *Server) newSession() string {
	raw := make([]byte, 24)
	rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	// 順帶清理過期 session
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = now.Add(sessionTTL)
	s.mu.Unlock()
	return token
}

func (s *Server) validSession(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[token]
	if !ok || time.Now().After(exp) {
		return false
	}
	return true
}

func (s *Server) dropSession(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func readCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.validSession(readCookie(r, sessionCookie)) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登入或 session 已過期"})
			return
		}
		next(w, r)
	}
}

// ---- 輔助 ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// SyncNow 配置變更後同步運行時：重建帳號索引 + 對齊隧道。
func (s *Server) SyncNow(ctx context.Context) error {
	c := s.cfg.Get()
	ups := make([]*config.Upstream, 0, len(c.Upstreams))
	for i := range c.Upstreams {
		ups = append(ups, &c.Upstreams[i])
	}
	s.authStore.Rebuild(ups)
	return s.tm.Sync(ctx, ups)
}

// errCollision 生成值與現有配置衝突，需重試。
var errCollision = fmt.Errorf("生成的 ID/帳號碰撞，請重試")

// newUpstreamID 生成候選上游 ID（鎖外呼叫；最終唯一性在 Update 內驗證）。
func newUpstreamID() string {
	raw := make([]byte, 4)
	rand.Read(raw)
	return "u" + base64.RawURLEncoding.EncodeToString(raw)
}

// genAccount 生成候選帳密對（鎖外呼叫）。
func genAccount() (string, string) {
	return auth.GenerateUsername(), auth.GeneratePassword()
}

// addUpstream 追加一個上游（ID/帳號碰撞自動重試），返回視圖。
func (s *Server) addUpstream(name string, conf warp.Conf) (upstreamView, error) {
	for i := 0; i < 50; i++ {
		id := newUpstreamID()
		user, pass := genAccount()
		view := upstreamView{ID: id, Username: user, Password: pass}
		err := s.cfg.Update(func(c *config.Config) error {
			if _, exists := c.UpstreamByID(id); exists {
				return errCollision
			}
			for _, u := range c.Upstreams {
				if u.Account.Username == user {
					return errCollision
				}
			}
			if strings.TrimSpace(name) == "" {
				name = user
			}
			c.Upstreams = append(c.Upstreams, config.Upstream{
				ID:            id,
				Name:          strings.TrimSpace(name),
				Enabled:       true,
				PrivateKey:    conf.PrivateKey,
				PeerPublicKey: conf.PeerPublicKey,
				Endpoint:      conf.Endpoint,
				Addresses:     conf.Addresses,
				Account:       config.Account{Username: user, Password: pass},
			})
			return nil
		})
		if err == nil {
			return view, nil
		}
		if err != errCollision {
			return upstreamView{}, err
		}
	}
	return upstreamView{}, fmt.Errorf("無法生成不重複的 ID/帳號（內部錯誤）")
}

// ---- handlers ----

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "請求格式錯誤"})
		return
	}
	expected := s.cfg.Get().AdminPassword
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(expected)) != 1 {
		time.Sleep(300 * time.Millisecond) // 減緩暴力嘗試
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "密碼錯誤"})
		return
	}
	token := s.newSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.dropSession(readCookie(r, sessionCookie))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	c := s.cfg.Get()
	states := s.tm.States()
	snap := s.stats.Snapshot()

	type upView struct {
		ID        string              `json:"id"`
		Name      string              `json:"name"`
		Enabled   bool                `json:"enabled"`
		Username  string              `json:"username"`
		Healthy   bool                `json:"healthy"`
		LastCheck string              `json:"last_check"`
		LastError string              `json:"last_error"`
		Rebuilds  int64               `json:"rebuilds"`
		Running   bool                `json:"running"`
		Stats     stats.UpstreamStats `json:"stats"`
	}
	ups := make([]upView, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		st := states[u.ID]
		ups = append(ups, upView{
			ID:        u.ID,
			Name:      u.Name,
			Enabled:   u.Enabled,
			Username:  u.Account.Username,
			Healthy:   st.Healthy,
			LastCheck: st.LastCheck.Format(time.RFC3339),
			LastError: st.LastError,
			Rebuilds:  st.Rebuilds,
			Running:   st.Running,
			Stats:     snap.Upstreams[u.ID],
		})
	}

	type acctView struct {
		Username string             `json:"username"`
		Upstream string             `json:"upstream"`
		Stats    stats.AccountStats `json:"stats"`
	}
	accts := make([]acctView, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		accts = append(accts, acctView{
			Username: u.Account.Username,
			Upstream: u.ID,
			Stats:    snap.Accounts[u.Account.Username],
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"upstreams": ups,
		"accounts":  accts,
		"settings": map[string]any{
			"listen_socks5": c.ListenSocks5,
			"listen_http":   c.ListenHTTP,
			"listen_web":    c.ListenWeb,
			"health":        c.HealthCheck,
		},
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.stats.Snapshot())
}

// upstreamView 上游敏感欄位視圖（自動註冊/導入/重生成後返回）。
type upstreamView struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleAutoRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Count int `json:"count"`
	}
	if err := readJSON(r, &body); err != nil || body.Count < 1 || body.Count > 10 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "count 需為 1..10"})
		return
	}

	var created []upstreamView
	for i := 0; i < body.Count; i++ {
		conf, err := s.register(r.Context())
		if err != nil {
			// 已成功的照常入庫；返回部分結果與錯誤說明
			if len(created) > 0 {
				if syncErr := s.SyncNow(r.Context()); syncErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]any{
						"error":   "隧道同步失敗: " + syncErr.Error(),
						"created": created,
					})
					return
				}
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"error":   fmt.Sprintf("第 %d 個帳號註冊失敗（CF API）: %v", i+1, err),
					"created": created,
				})
			} else {
				writeJSON(w, http.StatusBadGateway, map[string]string{
					"error": fmt.Sprintf("WARP 註冊失敗: %v", err),
				})
			}
			return
		}
		view, err := s.addUpstream("", conf)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		created = append(created, view)
	}
	if err := s.SyncNow(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "配置已保存但隧道同步失敗: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": created})
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Conf string `json:"conf"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &body); err != nil || strings.TrimSpace(body.Conf) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 conf 內容"})
		return
	}
	conf, err := warp.ParseConf(body.Conf)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	view, err := s.addUpstream(body.Name, conf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.SyncNow(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "配置已保存但隧道同步失敗: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handlePatchUpstream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "請求格式錯誤"})
		return
	}
	if err := s.patchUpstream(id, body.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := s.SyncNow(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// patchUpstream 修改上游啟用狀態（抽離以便 credentials 端點復用鎖語義）。
func (s *Server) patchUpstream(id string, enabled bool) error {
	return s.cfg.Update(func(c *config.Config) error {
		u, ok := c.UpstreamByID(id)
		if !ok {
			return fmt.Errorf("上游 %s 不存在", id)
		}
		u.Enabled = enabled
		return nil
	})
}

// handleGetCredentials 按需返回單個上游的帳密（複製代理連結用）。
// 概覽 API 不常駐暴露密碼，僅此顯式端點按需提供（需 session）。
func (s *Server) handleGetCredentials(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := s.cfg.Get()
	u, ok := c.UpstreamByID(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "上游不存在"})
		return
	}
	writeJSON(w, http.StatusOK, upstreamView{ID: u.ID, Username: u.Account.Username, Password: u.Account.Password})
}

func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tn, ok := s.tm.Get(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "隧道不存在（上游可能未啟用）"})
		return
	}
	if err := tn.Rebuild(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleRegenCredentials(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var view upstreamView
	var ok bool
	for i := 0; i < 50; i++ {
		user, pass := genAccount()
		candidate := upstreamView{Username: user, Password: pass}
		err := s.cfg.Update(func(c *config.Config) error {
			u, exists := c.UpstreamByID(id)
			if !exists {
				return fmt.Errorf("上游 %s 不存在", id)
			}
			for _, other := range c.Upstreams {
				if other.Account.Username == user {
					return errCollision
				}
			}
			u.Account.Username = user
			u.Account.Password = pass
			u.Name = user
			return nil
		})
		if err == errCollision {
			continue
		}
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		view, ok = candidate, true
		break
	}
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "帳號生成失敗"})
		return
	}
	if err := s.SyncNow(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.cfg.Update(func(c *config.Config) error {
		for i, u := range c.Upstreams {
			if u.ID == id {
				c.Upstreams = append(c.Upstreams[:i], c.Upstreams[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("上游 %s 不存在", id)
	})
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err := s.SyncNow(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ListenSocks5 string                    `json:"listen_socks5"`
		ListenHTTP   string                    `json:"listen_http"`
		ListenWeb    string                    `json:"listen_web"`
		Health       *config.HealthCheckConfig `json:"health"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "請求格式錯誤"})
		return
	}
	err := s.cfg.Update(func(c *config.Config) error {
		if v := body.ListenSocks5; v != "" {
			c.ListenSocks5 = v
		}
		if v := body.ListenHTTP; v != "" {
			c.ListenHTTP = v
		}
		if v := body.ListenWeb; v != "" {
			c.ListenWeb = v
		}
		if body.Health != nil {
			if body.Health.IntervalSeconds > 0 {
				c.HealthCheck.IntervalSeconds = body.Health.IntervalSeconds
			}
			if body.Health.FailureThreshold > 0 {
				c.HealthCheck.FailureThreshold = body.Health.FailureThreshold
			}
		}
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"note": "端口與健康參數已保存，重啟服務後生效"})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "請求格式錯誤"})
		return
	}
	if err := s.cfg.SetAdminPassword(body.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
