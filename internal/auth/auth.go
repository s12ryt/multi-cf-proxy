// Package auth 管理入站帳密（每個上游綁定一組自動生成的隨機帳密）與鑑權。
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"sync"

	"multi-cf-proxy/internal/config"
)

const (
	usernameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	passwordAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	usernamePrefix   = "warp-"
	usernameRandLen  = 4
	passwordLen      = 20
)

func randString(alphabet string, n int) string {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		// crypto/rand 失敗屬於系統級熵源故障，直接 panic 使問題顯性化
		panic("auth: 系統熵源不可用: " + err.Error())
	}
	for i, b := range out {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

// GenerateUsername 生成隨機用戶名：warp-XXXX（4 位小寫字母數字）。
func GenerateUsername() string {
	return usernamePrefix + randString(usernameAlphabet, usernameRandLen)
}

// GeneratePassword 生成 20 位隨機字母數字密碼（crypto/rand）。
func GeneratePassword() string {
	return randString(passwordAlphabet, passwordLen)
}

// entry 帳號索引項。
type entry struct {
	up *config.Upstream
}

// Store 用戶名→上游的併發安全鑑權索引。
type Store struct {
	mu      sync.RWMutex
	entries map[string]entry
}

// NewStore 依上游列表建立索引。只有「上游啟用且帳號未停用」的帳號可通過鑑權。
func NewStore(upstreams []*config.Upstream) *Store {
	s := &Store{}
	s.Rebuild(upstreams)
	return s
}

// Rebuild 以上游列表重建索引（Web 增刪改上游後呼叫）。
func (s *Store) Rebuild(upstreams []*config.Upstream) {
	entries := make(map[string]entry, len(upstreams))
	for _, up := range upstreams {
		if up == nil || up.Account.Username == "" {
			continue
		}
		entries[up.Account.Username] = entry{up: up}
	}
	s.mu.Lock()
	s.entries = entries
	s.mu.Unlock()
}

// Authenticate 校驗帳密；成功返回其綁定的上游。
// 密碼比較採用常數時間，避免時序側信道；未知用戶亦走一次比較以均衡耗時。
func (s *Store) Authenticate(username, password string) (*config.Upstream, bool) {
	s.mu.RLock()
	e, ok := s.entries[username]
	s.mu.RUnlock()
	if !ok {
		subtle.ConstantTimeCompare([]byte(password), []byte(password)) // 定時混淆
		return nil, false
	}
	if !e.up.Enabled || e.up.Account.Disabled {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(e.up.Account.Password)) != 1 {
		return nil, false
	}
	return e.up, true
}
