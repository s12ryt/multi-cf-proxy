package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.ListenSocks5 != ":1080" {
		t.Errorf("ListenSocks5 = %q, want :1080", c.ListenSocks5)
	}
	if c.ListenHTTP != ":8080" {
		t.Errorf("ListenHTTP = %q, want :8080", c.ListenHTTP)
	}
	if c.ListenWeb != ":8081" {
		t.Errorf("ListenWeb = %q, want :8081", c.ListenWeb)
	}
	if c.HealthCheck.IntervalSeconds != 30 {
		t.Errorf("HealthCheck.IntervalSeconds = %d, want 30", c.HealthCheck.IntervalSeconds)
	}
	if c.HealthCheck.FailureThreshold != 3 {
		t.Errorf("HealthCheck.FailureThreshold = %d, want 3", c.HealthCheck.FailureThreshold)
	}
	if c.AdminPassword != "" {
		t.Errorf("AdminPassword 應默認為空（首次啟動生成）, got %q", c.AdminPassword)
	}
}

func TestLoadNotFoundReturnsDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.json")
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load 不存在的文件不應報錯: %v", err)
	}
	if c.ListenSocks5 != ":1080" {
		t.Errorf("應返回默認配置, ListenSocks5 = %q", c.ListenSocks5)
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	orig := Default()
	orig.AdminPassword = "secret-admin"
	orig.Upstreams = []Upstream{
		{
			ID:            "u1",
			Name:          "warp-ab12",
			Enabled:       true,
			PrivateKey:    "PRIVATEKEYBASE64==",
			PeerPublicKey: "PEERPUB==",
			Endpoint:      "engage.cloudflareclient.com:2408",
			Addresses:     []string{"172.16.0.2/32", "2606:4700:110:8e12::/128"},
			Account: Account{
				Username: "warp-ab12",
				Password: "pw1234567890abcdef",
			},
		},
	}
	if err := orig.Save(path); err != nil {
		t.Fatalf("Save 失敗: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load 失敗: %v", err)
	}
	if got.AdminPassword != "secret-admin" {
		t.Errorf("AdminPassword = %q", got.AdminPassword)
	}
	if len(got.Upstreams) != 1 {
		t.Fatalf("Upstreams 數量 = %d, want 1", len(got.Upstreams))
	}
	u := got.Upstreams[0]
	if u.ID != "u1" || u.Name != "warp-ab12" || !u.Enabled {
		t.Errorf("上游基本欄位回讀不一致: %+v", u)
	}
	if u.PrivateKey != "PRIVATEKEYBASE64==" || u.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Errorf("WireGuard 欄位回讀不一致: %+v", u)
	}
	if u.Account.Username != "warp-ab12" || u.Account.Password != "pw1234567890abcdef" {
		t.Errorf("帳號回讀不一致: %+v", u.Account)
	}
}

func TestSaveProducesIndentedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Default().Save(path); err != nil {
		t.Fatalf("Save 失敗: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !json.Valid(raw) {
		t.Fatal("保存的文件應為合法 JSON")
	}
	if !strings.Contains(string(raw), "\n  ") {
		t.Error("保存的 JSON 應帶縮進（便於人工檢視）")
	}
}

func TestLoadInvalidJSONReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte("{not json"), 0o600)
	_, err := Load(path)
	if err == nil {
		t.Fatal("非法 JSON 應報錯")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("錯誤信息應包含文件路徑 %q: %v", path, err)
	}
}

func TestFillDefaultsKeepsExplicitValues(t *testing.T) {
	c := &Config{ListenSocks5: ":2000"}
	c.FillDefaults()
	if c.ListenSocks5 != ":2000" {
		t.Errorf("明確設置的值不應被覆蓋: %q", c.ListenSocks5)
	}
	if c.ListenHTTP != ":8080" {
		t.Errorf("空字段應補默認: %q", c.ListenHTTP)
	}
	if c.HealthCheck.IntervalSeconds != 30 {
		t.Errorf("健康檢查空值應補默認: %+v", c.HealthCheck)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"默認配置合法", func(c *Config) {}, false},
		{"SOCKS5 端口非法", func(c *Config) { c.ListenSocks5 = "abc" }, true},
		{"Web 端口非法", func(c *Config) { c.ListenWeb = "1:2:3" }, true},
		{"上游缺私鑰", func(c *Config) {
			c.Upstreams = []Upstream{{ID: "u1", Enabled: true}}
		}, true},
		{"停用上游免檢欄位", func(c *Config) {
			c.Upstreams = []Upstream{{ID: "u1", Enabled: false}}
		}, false},
		{"啟用上游缺帳號密碼", func(c *Config) {
			c.Upstreams = []Upstream{{
				ID: "u1", Enabled: true,
				PrivateKey: "k", PeerPublicKey: "p", Endpoint: "e:1", Addresses: []string{"172.16.0.2/32"},
				Account: Account{Username: "user"},
			}}
		}, true},
		{"健康檢查間隔為零", func(c *Config) { c.HealthCheck.IntervalSeconds = 0 }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Default()
			tt.mutate(c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpstreamByID(t *testing.T) {
	c := Default()
	c.Upstreams = []Upstream{{ID: "a", Name: "one"}, {ID: "b", Name: "two"}}
	if u, ok := c.UpstreamByID("b"); !ok || u.Name != "two" {
		t.Errorf("UpstreamByID(b) = %+v, %v", u, ok)
	}
	if _, ok := c.UpstreamByID("zz"); ok {
		t.Error("不存在的 ID 應返回 false")
	}
}
