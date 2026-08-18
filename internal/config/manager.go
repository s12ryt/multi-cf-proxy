package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
)

// Manager 配置管理器：串行化所有配置讀寫，保證「內存狀態 == 磁盤狀態」。
type Manager struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
}

// NewManager 載入（或初始化）配置文件。
func NewManager(path string) (*Manager, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}
	return &Manager{path: path, cfg: cfg}, nil
}

// Path 返回配置文件路徑。
func (m *Manager) Path() string { return m.path }

// Get 返回當前配置指針（調用方只讀；需修改請走 Update）。
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// Update 在鎖內修改配置：mutate → Validate → Save，任一步失敗即整體回滾。
func (m *Manager) Update(mutate func(c *Config) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 深拷貝一份作為事務工作區
	working, err := cloneConfig(m.cfg)
	if err != nil {
		return fmt.Errorf("複製配置失敗: %w", err)
	}
	if err := mutate(working); err != nil {
		return err
	}
	if err := working.Validate(); err != nil {
		return fmt.Errorf("修改後的配置無效: %w", err)
	}
	if err := working.Save(m.path); err != nil {
		return fmt.Errorf("保存配置失敗: %w", err)
	}
	m.cfg = working
	return nil
}

// EnsureAdminPassword 若管理員密碼為空則生成隨機密碼並持久化；返回是否生成。
func (m *Manager) EnsureAdminPassword() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cfg.AdminPassword != "" {
		return false
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic("config: 系統熵源不可用: " + err.Error())
	}
	m.cfg.AdminPassword = base64.RawURLEncoding.EncodeToString(raw)
	if err := m.cfg.Save(m.path); err != nil {
		// 寫盤失敗不靜默：密碼只在內存會導致重啟後失效
		panic("config: 持久化管理員密碼失敗: " + err.Error())
	}
	return true
}

// SetAdminPassword 直接設置管理員密碼並持久化（Web 修改密碼用）。
func (m *Manager) SetAdminPassword(pw string) error {
	return m.Update(func(c *Config) error {
		if len(pw) < 8 {
			return fmt.Errorf("管理員密碼長度至少 8 位")
		}
		c.AdminPassword = pw
		return nil
	})
}

// cloneConfig 深拷貝（經 JSON 序列化往返，簡單可靠）。
func cloneConfig(c *Config) (*Config, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var out Config
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
