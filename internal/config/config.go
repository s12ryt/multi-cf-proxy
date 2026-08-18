// Package config 定義「多開CF代理」的單一 JSON 配置結構與讀寫。
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// HealthCheckConfig 健康檢查參數。
type HealthCheckConfig struct {
	IntervalSeconds  int `json:"interval_seconds"`
	FailureThreshold int `json:"failure_threshold"`
}

// Account 綁定在某個上游的入站帳密（用戶名:密碼）。
type Account struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Disabled bool   `json:"disabled"`
}

// Upstream 一個 Cloudflare WARP 隧道上游及其綁定帳號。
type Upstream struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	PrivateKey    string   `json:"private_key"`     // WireGuard 本端私鑰（base64）
	PeerPublicKey string   `json:"peer_public_key"` // 對端（WARP）公鑰
	Endpoint      string   `json:"endpoint"`        // host:port
	Addresses     []string `json:"addresses"`       // 本端隧道地址（含掩碼）
	Account       Account  `json:"account"`
}

// Config 頂層配置，持久化為單一 JSON 文件。
type Config struct {
	AdminPassword string            `json:"admin_password"`
	ListenSocks5  string            `json:"listen_socks5"`
	ListenHTTP    string            `json:"listen_http"`
	ListenWeb     string            `json:"listen_web"`
	HealthCheck   HealthCheckConfig `json:"health_check"`
	Upstreams     []Upstream        `json:"upstreams"`
}

// Default 返回默認配置。AdminPassword 留空，由首次啟動流程生成。
func Default() *Config {
	return &Config{
		ListenSocks5: ":1080",
		ListenHTTP:   ":8080",
		ListenWeb:    ":8081",
		HealthCheck: HealthCheckConfig{
			IntervalSeconds:  30,
			FailureThreshold: 3,
		},
		Upstreams: []Upstream{},
	}
}

// FillDefaults 僅對空缺字段補默認值，不覆蓋明確設置的值。
func (c *Config) FillDefaults() {
	d := Default()
	if c.ListenSocks5 == "" {
		c.ListenSocks5 = d.ListenSocks5
	}
	if c.ListenHTTP == "" {
		c.ListenHTTP = d.ListenHTTP
	}
	if c.ListenWeb == "" {
		c.ListenWeb = d.ListenWeb
	}
	if c.HealthCheck.IntervalSeconds <= 0 {
		c.HealthCheck.IntervalSeconds = d.HealthCheck.IntervalSeconds
	}
	if c.HealthCheck.FailureThreshold <= 0 {
		c.HealthCheck.FailureThreshold = d.HealthCheck.FailureThreshold
	}
	if c.Upstreams == nil {
		c.Upstreams = []Upstream{}
	}
}

// Validate 檢查配置語義合法性；端口需可解析為 host:port。
func (c *Config) Validate() error {
	for _, p := range []struct{ name, val string }{
		{"listen_socks5", c.ListenSocks5},
		{"listen_http", c.ListenHTTP},
		{"listen_web", c.ListenWeb},
	} {
		if _, _, err := net.SplitHostPort(p.val); err != nil {
			return fmt.Errorf("%s 不是合法的 host:port（%q）: %w", p.name, p.val, err)
		}
	}
	if c.HealthCheck.IntervalSeconds <= 0 {
		return fmt.Errorf("health_check.interval_seconds 必須大於 0")
	}
	if c.HealthCheck.FailureThreshold <= 0 {
		return fmt.Errorf("health_check.failure_threshold 必須大於 0")
	}
	seen := map[string]bool{}
	for i, u := range c.Upstreams {
		if u.ID == "" {
			return fmt.Errorf("upstreams[%d].id 不可為空", i)
		}
		if seen[u.ID] {
			return fmt.Errorf("upstreams[%d].id 重複: %s", i, u.ID)
		}
		seen[u.ID] = true
		if !u.Enabled {
			continue // 停用的上游允許欄位不全，啟用時才校驗
		}
		if u.PrivateKey == "" || u.PeerPublicKey == "" {
			return fmt.Errorf("upstreams[%d]（%s）缺少 WireGuard 金鑰", i, u.Name)
		}
		if u.Endpoint == "" {
			return fmt.Errorf("upstreams[%d]（%s）缺少 endpoint", i, u.Name)
		}
		if len(u.Addresses) == 0 {
			return fmt.Errorf("upstreams[%d]（%s）缺少隧道地址", i, u.Name)
		}
		if u.Account.Username == "" || u.Account.Password == "" {
			return fmt.Errorf("upstreams[%d]（%s）缺少綁定帳號或密碼", i, u.Name)
		}
	}
	return nil
}

// Load 從 path 讀取配置；文件不存在時返回默認配置（首次啟動場景）。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		c := Default()
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("讀取配置 %s 失敗: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("解析配置 %s 失敗: %w", path, err)
	}
	c.FillDefaults()
	return &c, nil
}

// Save 以縮進 JSON 原子寫入（臨時文件 + rename），避免中途崩潰損壞配置。
func (c *Config) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("建立配置目錄失敗: %w", err)
		}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失敗: %w", err)
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("寫入臨時配置失敗: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替換配置文件失敗: %w", err)
	}
	return nil
}

// UpstreamByID 按 ID 查找上游。
func (c *Config) UpstreamByID(id string) (*Upstream, bool) {
	for i := range c.Upstreams {
		if c.Upstreams[i].ID == id {
			return &c.Upstreams[i], true
		}
	}
	return nil, false
}
