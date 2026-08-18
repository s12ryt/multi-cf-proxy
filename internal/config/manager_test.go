package config

import (
	"path/filepath"
	"sync"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManagerFirstBootGeneratesAdminPassword(t *testing.T) {
	m := newTestManager(t)
	changed := m.EnsureAdminPassword()
	if !changed {
		t.Error("首次啟動應生成管理員密碼")
	}
	if m.Get().AdminPassword == "" || len(m.Get().AdminPassword) < 12 {
		t.Errorf("生成的密碼不合格: %q", m.Get().AdminPassword)
	}
	// 應已持久化
	m2, err := NewManager(filepath.Dir(m.Path()) + string(filepath.Separator) + filepath.Base(m.Path()))
	if err != nil {
		t.Fatal(err)
	}
	if m2.Get().AdminPassword != m.Get().AdminPassword {
		t.Error("生成的密碼應已寫盤")
	}
	if m2.EnsureAdminPassword() {
		t.Error("第二次啟動不應再生成")
	}
}

func TestManagerUpdatePersists(t *testing.T) {
	m := newTestManager(t)
	err := m.Update(func(c *Config) error {
		c.Upstreams = append(c.Upstreams, Upstream{
			ID: "u1", Name: "warp-test", Enabled: true,
			PrivateKey: "k", PeerPublicKey: "p", Endpoint: "e:1",
			Addresses: []string{"172.16.0.2/32"},
			Account:   Account{Username: "warp-aaaa", Password: "pw"},
		})
		return nil
	})
	if err != nil {
		t.Fatalf("Update 失敗: %v", err)
	}
	m2, err := NewManager(m.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.Get().Upstreams) != 1 || m2.Get().Upstreams[0].ID != "u1" {
		t.Errorf("Update 未持久化: %+v", m2.Get().Upstreams)
	}
}

func TestManagerUpdateRejectsInvalid(t *testing.T) {
	m := newTestManager(t)
	err := m.Update(func(c *Config) error {
		c.ListenSocks5 = "bad"
		return nil
	})
	if err == nil {
		t.Fatal("非法修改應被拒")
	}
	if m.Get().ListenSocks5 == "bad" {
		t.Error("被拒的修改不應殘留內存")
	}
}

func TestManagerConcurrentUpdates(t *testing.T) {
	m := newTestManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = m.Update(func(c *Config) error {
				c.Upstreams = append(c.Upstreams, Upstream{ID: string(rune('a' + i)), Enabled: false})
				return nil
			})
			_ = m.Get()
		}(i)
	}
	wg.Wait()
	if len(m.Get().Upstreams) != 16 {
		t.Errorf("併發更新丟失: %d", len(m.Get().Upstreams))
	}
}
