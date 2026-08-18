// Package warp 提供 Cloudflare WARP 接入能力：
// WireGuard 配置解析（手動導入）與 WARP 註冊 API 客戶端（自動註冊）。
package warp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// DefaultEndpoint WARP 標準 WireGuard 端點（DNS 輪詢到任一 CF 接入點）。
const DefaultEndpoint = "engage.cloudflareclient.com:2408"

// DefaultBaseURL WARP 註冊 API（與 wgcf 相同的客戶端接口版本）。
const DefaultBaseURL = "https://api.cloudflareclient.com/v0a2158"

// Conf 一條 WARP/WireGuard 隧道所需的全部參數。
type Conf struct {
	PrivateKey    string   // base64
	PeerPublicKey string   // base64
	Endpoint      string   // host:port
	Addresses     []string // 含前綴長度
}

// GenerateKeypair 生成 WireGuard curve25519 金鑰對（base64）。
func GenerateKeypair() (privateKey, publicKey string, err error) {
	var priv [32]byte
	if _, err = rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("讀取熵源失敗: %w", err)
	}
	// curve25519 私鑰需按規範 clamp
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("推導公鑰失敗: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// ParseConf 解析 wgcf / WireGuard 標準 conf 文本。
func ParseConf(text string) (Conf, error) {
	var (
		c           Conf
		section     string
		sawPeerKey  bool
		sawEndpoint bool
	)
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch section + "." + key {
		case "interface.privatekey":
			c.PrivateKey = value
		case "interface.address":
			for _, a := range strings.Split(value, ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					c.Addresses = append(c.Addresses, a)
				}
			}
		case "peer.publickey":
			c.PeerPublicKey = value
			sawPeerKey = true
		case "peer.endpoint":
			c.Endpoint = value
			sawEndpoint = true
		}
	}
	if err := sc.Err(); err != nil {
		return Conf{}, fmt.Errorf("讀取配置失敗: %w", err)
	}

	var problems []string
	if c.PrivateKey == "" {
		problems = append(problems, "缺少 [Interface] PrivateKey")
	} else if !validWGKey(c.PrivateKey) {
		problems = append(problems, "PrivateKey 不是合法的 32 位元組 base64")
	}
	if !sawPeerKey {
		problems = append(problems, "缺少 [Peer] PublicKey")
	} else if !validWGKey(c.PeerPublicKey) {
		problems = append(problems, "Peer PublicKey 不是合法的 32 位元組 base64")
	}
	if !sawEndpoint {
		problems = append(problems, "缺少 [Peer] Endpoint")
	} else if _, _, err := net.SplitHostPort(c.Endpoint); err != nil {
		problems = append(problems, fmt.Sprintf("Endpoint %q 不是合法 host:port", c.Endpoint))
	}
	if len(c.Addresses) == 0 {
		problems = append(problems, "缺少 [Interface] Address")
	}
	if len(problems) > 0 {
		return Conf{}, fmt.Errorf("WireGuard 配置無效: %s", strings.Join(problems, "; "))
	}
	if c.Endpoint == "" {
		c.Endpoint = DefaultEndpoint
	}
	return c, nil
}

func validWGKey(s string) bool {
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

// ---- WARP 註冊 API 客戶端 ----

// Client WARP 註冊客戶端。零值不可用，透過 NewClient 建立。
type Client struct {
	http    *http.Client
	baseURL string
}

// Option Client 配置選項。
type Option func(*Client)

// WithBaseURL 覆蓋 API 基地址（測試用）。
func WithBaseURL(u string) Option {
	return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") }
}

// NewClient 建立註冊客戶端。
func NewClient(opts ...Option) *Client {
	c := &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		baseURL: DefaultBaseURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// v6v4Addresses 真實 CF API 的 addresses 欄位格式（wgcf openapi spec）：
// 物件 {"v4": "<裸IP>", "v6": "<裸IP>"}，生成配置時補 /32 與 /128。
type v6v4Addresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type regResponse struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses v6v4Addresses `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
		} `json:"peers"`
	} `json:"config"`
	Errors []struct {
		Code int `json:"code"`
	} `json:"errors"`
}

type regRequest struct {
	FCMToken     string `json:"fcm_token"`
	InstallID    string `json:"install_id"`
	Key          string `json:"key"`
	Locale       string `json:"locale"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	TOS          string `json:"tos"`
	Type         string `json:"type"`
}

// Register 註冊一個新 WARP 帳號並返回可用隧道配置：
// 自生成金鑰對 → POST 註冊 → GET 讀取分配的隧道地址與對端公鑰。
func (c *Client) Register(ctx context.Context) (Conf, error) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		return Conf{}, err
	}

	reg := regRequest{
		Key:          pub,
		Locale:       "en_US",
		Model:        "Linux",
		SerialNumber: randomDigits(20),
		TOS:          time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Type:         "Android",
	}
	body, _ := json.Marshal(reg)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/reg", bytes.NewReader(body))
	if err != nil {
		return Conf{}, fmt.Errorf("建立註冊請求失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return Conf{}, fmt.Errorf("WARP 註冊請求失敗（CF API 不可達）: %w", err)
	}
	defer resp.Body.Close()
	var regResp regResponse
	if resp.StatusCode != http.StatusOK {
		_ = json.NewDecoder(resp.Body).Decode(&regResp)
		return Conf{}, fmt.Errorf("WARP 註冊被拒（HTTP %d，code=%v）", resp.StatusCode, apiErrCode(regResp))
	}
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return Conf{}, fmt.Errorf("解析註冊回應失敗: %w", err)
	}

	// 第二步：以 token 讀取完整配置（隧道地址 + 對端公鑰）
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/reg/"+regResp.ID, nil)
	if err != nil {
		return Conf{}, fmt.Errorf("建立配置請求失敗: %w", err)
	}
	req2.Header.Set("Authorization", "Bearer "+regResp.Token)
	req2.Header.Set("User-Agent", "okhttp/3.12.1")

	resp2, err := c.http.Do(req2)
	if err != nil {
		return Conf{}, fmt.Errorf("讀取 WARP 配置失敗: %w", err)
	}
	defer resp2.Body.Close()
	var full regResponse
	if resp2.StatusCode != http.StatusOK {
		_ = json.NewDecoder(resp2.Body).Decode(&full)
		return Conf{}, fmt.Errorf("讀取 WARP 配置被拒（HTTP %d，code=%v）", resp2.StatusCode, apiErrCode(full))
	}
	if err := json.NewDecoder(resp2.Body).Decode(&full); err != nil {
		return Conf{}, fmt.Errorf("解析 WARP 配置失敗: %w", err)
	}
	if len(full.Config.Peers) == 0 || full.Config.Peers[0].PublicKey == "" {
		return Conf{}, fmt.Errorf("WARP 配置缺少對端公鑰")
	}
	// 裸 IP 補前綴長度（與 wgcf 生成行為一致：v4/32、v6/128）
	var addrs []string
	if v4 := full.Config.Interface.Addresses.V4; v4 != "" {
		addrs = append(addrs, v4+"/32")
	}
	if v6 := full.Config.Interface.Addresses.V6; v6 != "" {
		addrs = append(addrs, v6+"/128")
	}
	if len(addrs) == 0 {
		return Conf{}, fmt.Errorf("WARP 配置缺少隧道地址")
	}

	return Conf{
		PrivateKey:    priv,
		PeerPublicKey: full.Config.Peers[0].PublicKey,
		Endpoint:      DefaultEndpoint,
		Addresses:     addrs,
	}, nil
}

func apiErrCode(r regResponse) string {
	codes := make([]string, 0, len(r.Errors))
	for _, e := range r.Errors {
		codes = append(codes, fmt.Sprintf("%d", e.Code))
	}
	if len(codes) == 0 {
		return "unknown"
	}
	return strings.Join(codes, ",")
}

func maskToken(tok string) string {
	if len(tok) <= 4 {
		return "****"
	}
	return tok[:4] + "****"
}

func randomDigits(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	out := make([]byte, n)
	for i, v := range b {
		out[i] = '0' + v%10
	}
	return string(out)
}
