package auth

import (
	"sync"
	"testing"

	"multi-cf-proxy/internal/config"
)

func mkUpstreams() []*config.Upstream {
	return []*config.Upstream{
		{ID: "u1", Enabled: true, Account: config.Account{Username: "warp-aaaa", Password: "password111"}},
		{ID: "u2", Enabled: true, Account: config.Account{Username: "warp-bbbb", Password: "password222"}},
		{ID: "u3", Enabled: false, Account: config.Account{Username: "warp-cccc", Password: "password333"}},
		{ID: "u4", Enabled: true, Account: config.Account{Username: "warp-dddd", Password: "password444", Disabled: true}},
	}
}

func TestGenerateUsernameFormat(t *testing.T) {
	for i := 0; i < 50; i++ {
		u := GenerateUsername()
		if len(u) != len("warp-xxxx") {
			t.Fatalf("用戶名長度 = %d (%q), want 9", len(u), u)
		}
		if u[:5] != "warp-" {
			t.Fatalf("用戶名前綴 = %q, want warp-", u[:5])
		}
		for _, c := range u[5:] {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				t.Fatalf("用戶名含非法字符 %q in %q", c, u)
			}
		}
	}
}

func TestGeneratePasswordFormat(t *testing.T) {
	for i := 0; i < 50; i++ {
		p := GeneratePassword()
		if len(p) != 20 {
			t.Fatalf("密碼長度 = %d, want 20", len(p))
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				t.Fatalf("密碼含非法字符 %q in %q", c, p)
			}
		}
	}
}

func TestGenerateRandomness(t *testing.T) {
	seenU, seenP := map[string]bool{}, map[string]bool{}
	for i := 0; i < 100; i++ {
		u, p := GenerateUsername(), GeneratePassword()
		if seenU[u] {
			t.Errorf("用戶名重複: %q", u)
		}
		if seenP[p] {
			t.Errorf("密碼重複: %q", p)
		}
		seenU[u], seenP[p] = true, true
	}
}

func TestAuthenticate(t *testing.T) {
	s := NewStore(mkUpstreams())
	tests := []struct {
		name     string
		user     string
		pass     string
		wantOK   bool
		wantUpID string
	}{
		{"正確帳密", "warp-aaaa", "password111", true, "u1"},
		{"錯誤密碼", "warp-aaaa", "wrong", false, ""},
		{"未知用戶", "nobody", "password111", false, ""},
		{"停用上游的帳號", "warp-cccc", "password333", false, ""},
		{"帳號本身停用", "warp-dddd", "password444", false, ""},
		{"空帳密", "", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up, ok := s.Authenticate(tt.user, tt.pass)
			if ok != tt.wantOK {
				t.Fatalf("Authenticate(%q, ***) ok = %v, want %v", tt.user, ok, tt.wantOK)
			}
			if ok && up.ID != tt.wantUpID {
				t.Errorf("綁定上游 ID = %q, want %q", up.ID, tt.wantUpID)
			}
		})
	}
}

func TestRebuild(t *testing.T) {
	ups := mkUpstreams()
	s := NewStore(ups)
	if _, ok := s.Authenticate("warp-eeee", "password555"); ok {
		t.Fatal("尚未加入的帳號不應通過")
	}
	ups = append(ups, &config.Upstream{ID: "u5", Enabled: true, Account: config.Account{Username: "warp-eeee", Password: "password555"}})
	s.Rebuild(ups)
	up, ok := s.Authenticate("warp-eeee", "password555")
	if !ok || up.ID != "u5" {
		t.Fatalf("Rebuild 後應能鑑權新帳號: ok=%v up=%+v", ok, up)
	}
}

func TestAuthenticateConcurrent(t *testing.T) {
	s := NewStore(mkUpstreams())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				up, ok := s.Authenticate("warp-aaaa", "password111")
				if !ok || up.ID != "u1" {
					t.Errorf("併發鑑權失敗: ok=%v", ok)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
