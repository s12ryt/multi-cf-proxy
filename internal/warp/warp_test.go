package warp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleConf = `[Interface]
PrivateKey = yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=
Address = 172.16.0.2/32, 2606:4700:110:8e12::/128
DNS = 1.1.1.1

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
`

func TestParseConf(t *testing.T) {
	c, err := ParseConf(sampleConf)
	if err != nil {
		t.Fatalf("ParseConf 失敗: %v", err)
	}
	if c.PrivateKey != "yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=" {
		t.Errorf("PrivateKey = %q", c.PrivateKey)
	}
	if c.PeerPublicKey != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Errorf("PeerPublicKey = %q", c.PeerPublicKey)
	}
	if c.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Errorf("Endpoint = %q", c.Endpoint)
	}
	if len(c.Addresses) != 2 {
		t.Fatalf("Addresses = %v, want 2", c.Addresses)
	}
	if c.Addresses[0] != "172.16.0.2/32" || c.Addresses[1] != "2606:4700:110:8e12::/128" {
		t.Errorf("Addresses 內容 = %v", c.Addresses)
	}
}

func TestParseConfInvalid(t *testing.T) {
	tests := []struct {
		name string
		conf string
	}{
		{"空配置", ""},
		{"缺 Interface", "[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = e:1\n"},
		{"缺 Peer", "[Interface]\nPrivateKey = yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=\nAddress = 172.16.0.2/32\n"},
		{"私鑰非 base64", "[Interface]\nPrivateKey = !!!not-base64!!!\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = e:1\n"},
		{"公鑰長度錯誤", "[Interface]\nPrivateKey = yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = c2hvcnQ=\nEndpoint = e:1\n"},
		{"無地址", "[Interface]\nPrivateKey = yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=\n\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = e:1\n"},
		{"endpoint 非法", "[Interface]\nPrivateKey = yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=\nAddress = 172.16.0.2/32\n\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\nEndpoint = no-port\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConf(tt.conf); err == nil {
				t.Fatalf("應報錯但通過: %q", tt.conf)
			}
		})
	}
}

func TestGenerateKeypair(t *testing.T) {
	priv1, pub1, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if priv1 == priv2 || pub1 == pub2 {
		t.Error("兩次生成的金鑰不應相同")
	}
	raw, err := base64.StdEncoding.DecodeString(priv1)
	if err != nil || len(raw) != 32 {
		t.Errorf("私鑰應為 32 位元組 base64: %d, %v", len(raw), err)
	}
	raw, err = base64.StdEncoding.DecodeString(pub1)
	if err != nil || len(raw) != 32 {
		t.Errorf("公鑰應為 32 位元組 base64: %d, %v", len(raw), err)
	}
}

// realFormatConfig 鏡像真實 CF API 的 config 結構（依 wgcf openapi spec）：
// addresses 為 {v4, v6} 物件（裸 IP），生成配置時補 /32 與 /128。
const realFormatConfig = `"config": {
	"interface": {
		"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8e12::a1f5"}
	},
	"peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}]
}`

// TestRegister 成功路徑：mock CF 註冊 API（POST 註冊 + GET 取配置），格式按真實 API。
func TestRegister(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reg"):
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["key"] == nil || body["key"] == "" {
				w.WriteHeader(400)
				return
			}
			fmt.Fprintf(w, `{"id": "reg-123", "token": "tok-abc", %s}`, realFormatConfig)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/reg/reg-123"):
			auth := r.Header.Get("Authorization")
			if auth != "Bearer tok-abc" {
				w.WriteHeader(401)
				return
			}
			fmt.Fprintf(w, `{"id": "reg-123", "token": "tok-abc", %s}`, realFormatConfig)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	conf, err := client.Register(t.Context())
	if err != nil {
		t.Fatalf("Register 失敗: %v", err)
	}
	if conf.PeerPublicKey != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Errorf("PeerPublicKey = %q", conf.PeerPublicKey)
	}
	// 裸 IP 應已補上 /32 與 /128（與 wgcf 生成行為一致）
	if len(conf.Addresses) != 2 {
		t.Fatalf("Addresses = %v, want 2", conf.Addresses)
	}
	if conf.Addresses[0] != "172.16.0.2/32" {
		t.Errorf("v4 = %q, want 172.16.0.2/32", conf.Addresses[0])
	}
	if conf.Addresses[1] != "2606:4700:110:8e12::a1f5/128" {
		t.Errorf("v6 = %q, want 2606:4700:110:8e12::a1f5/128", conf.Addresses[1])
	}
	if conf.Endpoint == "" {
		t.Error("Endpoint 應有默認值")
	}
	if _, err := base64.StdEncoding.DecodeString(conf.PrivateKey); err != nil {
		t.Errorf("Register 應返回自生成私鑰: %v", err)
	}
}

// TestRegisterV4Only 真實 API 可能只配發 v4（v6 缺失）→ 僅產出 v4/32。
func TestRegisterV4Only(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := `"config": {"interface": {"addresses": {"v4": "172.16.0.9"}}, "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}]}`
		if r.Method == http.MethodPost {
			fmt.Fprintf(w, `{"id": "reg-1", "token": "t", %s}`, cfg)
			return
		}
		fmt.Fprintf(w, `{"id": "reg-1", "token": "t", %s}`, cfg)
	}))
	defer srv.Close()

	conf, err := NewClient(WithBaseURL(srv.URL)).Register(t.Context())
	if err != nil {
		t.Fatalf("Register 失敗: %v", err)
	}
	if len(conf.Addresses) != 1 || conf.Addresses[0] != "172.16.0.9/32" {
		t.Errorf("Addresses = %v, want [172.16.0.9/32]", conf.Addresses)
	}
}

// TestRegisterNoAddresses 兩族地址全缺 → 應明確報錯。
func TestRegisterNoAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := `"config": {"interface": {"addresses": {}}, "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}]}`
		fmt.Fprintf(w, `{"id": "reg-1", "token": "t", %s}`, cfg)
	}))
	defer srv.Close()

	if _, err := NewClient(WithBaseURL(srv.URL)).Register(t.Context()); err == nil {
		t.Fatal("無地址應報錯")
	}
}

func TestRegisterAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]any{"errors": []any{map[string]any{"code": 9431}}})
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	if _, err := client.Register(t.Context()); err == nil {
		t.Fatal("API 403 應報錯")
	}
}

func TestRegisterRegisterStepFails(t *testing.T) {
	// POST 成功但 GET 失敗（如 token 失效）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]any{"id": "reg-123", "token": "tok-abc"})
			return
		}
		w.WriteHeader(500)
	}))
	defer srv.Close()

	client := NewClient(WithBaseURL(srv.URL))
	if _, err := client.Register(t.Context()); err == nil {
		t.Fatal("第二步失敗應報錯")
	}
}
