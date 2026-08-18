package inbound

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/dispatcher"
	"multi-cf-proxy/internal/stats"
)

// newTestService 建立導向固定後端的 dispatcher 服務。
func newTestService(t *testing.T, backendAddr string) *dispatcher.Service {
	t.Helper()
	up := &config.Upstream{ID: "u1", Enabled: true, Account: config.Account{Username: "warp-aaaa", Password: "pw1"}}
	reg := &echoRegistry{t: &echoTunnel{id: "u1", target: backendAddr}}
	return dispatcher.NewService(auth.NewStore([]*config.Upstream{up}), reg, stats.NewCollector())
}

func startHTTP(t *testing.T) (proxyAddr string, backend *http.Server) {
	t.Helper()
	// 後端：回顯路徑與方法
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	be := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "path=%s method=%s", r.URL.Path, r.Method)
	})}
	go be.Serve(backendLn)
	t.Cleanup(func() { be.Close() })

	addr := startHTTPWithTarget(t, backendLn.Addr().String())
	return addr, be
}

// startHTTPWithTarget 啟動導向指定後端的代理。
func startHTTPWithTarget(t *testing.T, target string) (addr string) {
	t.Helper()
	svc := newTestService(t, target)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTP(svc)
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func httpProxyURL(t *testing.T, addr, user, pass string) *url.URL {
	t.Helper()
	return &url.URL{
		Scheme: "http",
		Host:   addr,
		User:   url.UserPassword(user, pass),
	}
}

func TestHTTPProxyGET(t *testing.T) {
	addr, _ := startHTTP(t)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(httpProxyURL(t, addr, "warp-aaaa", "pw1"))},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get("http://backend.test/hello?x=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "path=/hello method=GET" {
		t.Errorf("backend 回應 = %q", body)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}

func TestHTTPProxyNoAuthReturns407(t *testing.T) {
	addr, _ := startHTTP(t)
	client := &http.Client{
		Transport:     &http.Transport{Proxy: http.ProxyURL(httpProxyURL(t, addr, "warp-aaaa", ""))},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest("GET", "http://backend.test/x", nil)
	resp, err := client.Transport.RoundTrip(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("無帳密應 407, got %d", resp.StatusCode)
		}
		if resp.Header.Get("Proxy-Authenticate") == "" {
			t.Error("407 應帶 Proxy-Authenticate: Basic")
		}
		return
	}
	// 直接手動請求（某些 transport 對空 user 處理不同）
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	fmt.Fprintf(c, "GET http://backend.test/x HTTP/1.1\r\nHost: backend.test\r\n\r\n")
	r := bufio.NewReader(c)
	resp2, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("無帳密應 407, got %d", resp2.StatusCode)
	}
}

func TestHTTPProxyWrongPassword407(t *testing.T) {
	addr, _ := startHTTP(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("warp-aaaa:wrong"))
	fmt.Fprintf(c, "GET http://backend.test/x HTTP/1.1\r\nHost: backend.test\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("錯密碼應 407, got %d", resp.StatusCode)
	}
}

func TestHTTPProxyPOST(t *testing.T) {
	addr, _ := startHTTP(t)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(httpProxyURL(t, addr, "warp-aaaa", "pw1"))},
	}
	resp, err := client.Post("http://backend.test/submit", "text/plain", strings.NewReader("data"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "path=/submit method=POST" {
		t.Errorf("backend 回應 = %q", body)
	}
}

func TestHTTPProxyCONNECT(t *testing.T) {
	// 後端 echo（CONNECT 隧道的對象）
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	defer echoLn.Close()

	addr := startHTTPWithTarget(t, echoLn.Addr().String())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("warp-aaaa:pw1"))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", echoLn.Addr(), echoLn.Addr(), auth)
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT 應 200, got %d", resp.StatusCode)
	}
	// 隧道 echo 測試
	c.Write([]byte("ping"))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("隧道讀取失敗: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("echo = %q", buf)
	}
}

func TestHTTPProxyCONNECTWrongAuth(t *testing.T) {
	addr, _ := startHTTP(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("warp-aaaa:bad"))
	fmt.Fprintf(c, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT 錯密碼應 407, got %d", resp.StatusCode)
	}
}
