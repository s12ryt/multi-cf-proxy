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
	orig.HealthCheck.LatencyDiscardSeconds = 1.5
	orig.DNSCacheSeconds = 45
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
	if got.HealthCheck.LatencyDiscardSeconds != 1.5 {
		t.Errorf("延遲丟棄秒數回讀不一致: %v", got.HealthCheck.LatencyDiscardSeconds)
	}
	if got.DNSCacheSeconds != 45 {
		t.Errorf("DNS 快取秒數回讀不一致: %v", got.DNSCacheSeconds)
	}
}

// TestDNSCacheDefaultAndZero v1.6：缺鍵=60（存量升級自動受益）；顯式 0=停用；負值非法。
func TestDNSCacheDefaultAndZero(t *testing.T) {
	// 全新默認 60
	if d := Default(); d.DNSCacheSeconds != 60 {
		t.Errorf("Default DNSCacheSeconds = %d, want 60", d.DNSCacheSeconds)
	}
	dir := t.TempDir()

	// 存量配置（無 dns_cache_seconds 鍵）→ Load 補 60
	legacy := filepath.Join(dir, "legacy.json")
	os.WriteFile(legacy, []byte(`{"listen_socks5":":1080","listen_http":":8080","listen_web":":8081","health_check":{"interval_seconds":30,"failure_threshold":3}}`), 0o600)
	c, err := Load(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if c.DNSCacheSeconds != 60 {
		t.Errorf("缺鍵應補 60, got %d", c.DNSCacheSeconds)
	}

	// 顯式 0 → 停用（Load 不覆蓋）
	off := filepath.Join(dir, "off.json")
	os.WriteFile(off, []byte(`{"dns_cache_seconds":0,"health_check":{"interval_seconds":30,"failure_threshold":3}}`), 0o600)
	c, err = Load(off)
	if err != nil {
		t.Fatal(err)
	}
	if c.DNSCacheSeconds != 0 {
		t.Errorf("顯式 0 應保留為停用, got %d", c.DNSCacheSeconds)
	}

	// 負值 → Validate 拒絕
	c.DNSCacheSeconds = -1
	if err := c.Validate(); err == nil {
		t.Error("負值應非法")
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
	// 延遲丟棄 0 = 停用，屬合法值，不應被 FillDefaults 改寫
	if c.HealthCheck.LatencyDiscardSeconds != 0 {
		t.Errorf("延遲丟棄默認應為 0（停用）: %v", c.HealthCheck.LatencyDiscardSeconds)
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
		{"延遲丟棄秒數為負", func(c *Config) { c.HealthCheck.LatencyDiscardSeconds = -0.5 }, true},
		{"延遲丟棄零表示停用", func(c *Config) { c.HealthCheck.LatencyDiscardSeconds = 0 }, false},
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

func TestRoutingDefaults(t *testing.T) {
	c := Default()
	if c.Routing.SwitchMarginMS != 20 {
		t.Errorf("默認 switch_margin_ms = %d, want 20", c.Routing.SwitchMarginMS)
	}
	if c.Routing.PreferLowestLatency {
		t.Error("默認 prefer_lowest_latency 應為 false")
	}
}

func TestLoadRoutingMissingKeyFillsMargin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	// 存量配置：無 routing 區塊 → margin 補默認 20
	if err := os.WriteFile(path, []byte(`{"listen_socks5":":1080","listen_http":":8080","listen_web":":8081"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Routing.SwitchMarginMS != 20 {
		t.Errorf("缺 routing 鍵時 switch_margin_ms 應補 20, got %d", c.Routing.SwitchMarginMS)
	}
	if c.Routing.PreferLowestLatency {
		t.Error("缺 routing 鍵時 prefer_lowest_latency 應為 false")
	}
}

func TestLoadRoutingExplicitValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{"routing":{"prefer_lowest_latency":true,"switch_margin_ms":0}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Routing.PreferLowestLatency {
		t.Error("顯式 prefer_lowest_latency=true 應保留")
	}
	if c.Routing.SwitchMarginMS != 0 {
		t.Errorf("顯式 switch_margin_ms=0（停用防抖）應保留, got %d", c.Routing.SwitchMarginMS)
	}
}

func TestValidateRoutingNegativeMargin(t *testing.T) {
	c := Default()
	c.Routing.SwitchMarginMS = -1
	if err := c.Validate(); err == nil {
		t.Error("routing.switch_margin_ms 為負應驗證失敗")
	}
	c.Routing.SwitchMarginMS = 0
	if err := c.Validate(); err != nil {
		t.Errorf("switch_margin_ms=0 應合法: %v", err)
	}
}
