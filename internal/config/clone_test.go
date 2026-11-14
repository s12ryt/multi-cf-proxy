// 覆蓋 R7：配置事務拷貝的語意與成本契約。
// 行 14 深拷貝隔離（含 Addresses 切片）；行 56 事務回滾；行 76 基準。
package config

import (
	"path/filepath"
	"testing"
)

func sampleConfig() *Config {
	c := Default()
	c.AdminPassword = "pw"
	for i := 0; i < 8; i++ {
		c.Upstreams = append(c.Upstreams, Upstream{
			ID:            "u" + string(rune('1'+i)),
			Name:          "warp",
			Enabled:       true,
			PrivateKey:    "priv",
			PeerPublicKey: "pub",
			Endpoint:      "engage.cloudflareclient.com:2408",
			Addresses:     []string{"172.16.0.2/32", "fd01::5/128"},
			Account:       Account{Username: "warp-aaaa", Password: "pw"},
		})
	}
	return c
}

// TestCloneConfigIsolatesSlices 工作區與原配置不得共用任何可變結構。
func TestCloneConfigIsolatesSlices(t *testing.T) {
	src := sampleConfig()
	dst, err := cloneConfig(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(dst.Upstreams) != len(src.Upstreams) {
		t.Fatalf("上游數量 = %d, want %d", len(dst.Upstreams), len(src.Upstreams))
	}

	dst.Upstreams[0].Addresses[0] = "10.0.0.1/32"
	if src.Upstreams[0].Addresses[0] == "10.0.0.1/32" {
		t.Error("Addresses 切片仍與原配置共用底層陣列")
	}

	dst.Upstreams = append(dst.Upstreams, Upstream{ID: "extra"})
	if len(src.Upstreams) != 8 {
		t.Error("附加上游污染了原配置")
	}

	dst.Upstreams[1].Account.Password = "changed"
	if src.Upstreams[1].Account.Password == "changed" {
		t.Error("帳號欄位仍共用")
	}
}

// TestUpdateRollsBackOnInvalid 校驗失敗時原配置不得被改動。
func TestUpdateRollsBackOnInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	src := sampleConfig()
	if err := src.Save(path); err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	err = m.Update(func(c *Config) error {
		c.ListenSocks5 = "" // 觸發 Validate 失敗
		return nil
	})
	if err == nil {
		t.Fatal("無效配置應被拒絕")
	}
	if got := m.Get().ListenSocks5; got == "" {
		t.Error("事務失敗後原配置被污染")
	}
}

func BenchmarkCloneConfig(b *testing.B) {
	src := sampleConfig()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cloneConfig(src)
	}
}
