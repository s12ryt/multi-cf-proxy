package inbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"multi-cf-proxy/internal/dispatcher"
)

// hopHeaders 逐跳標頭，轉發前必須剝除（RFC 7230 第 6.1 節）。
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// HTTP 入站代理服務器（Basic 認證 + CONNECT 隧道 + 普通方法轉發）。
type HTTP struct {
	svc *dispatcher.Service
	wg  sync.WaitGroup
}

// NewHTTP 建立 HTTP 代理服務。
func NewHTTP(svc *dispatcher.Service) *HTTP {
	return &HTTP{svc: svc}
}

// Serve 接受並處理連線，直到 listener 關閉。
func (h *HTTP) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.handle(conn)
		}()
	}
}

// Stop 等待全部活躍連線結束。
func (h *HTTP) Stop() { h.wg.Wait() }

func (h *HTTP) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Time{})

		user, pass, hasAuth := parseProxyAuth(req.Header.Get("Proxy-Authorization"))
		if !hasAuth || !h.svc.Authenticate(user, pass) {
			writeProxyAuthRequired(conn)
			return
		}

		if req.Method == http.MethodConnect {
			h.tunnel(conn, br, user, pass, req)
			return // CONNECT 之後連線為原始隧道，不再循環
		}
		if err := h.forward(conn, br, req, user, pass); err != nil {
			return
		}
	}
}

// writeProxyAuthRequired 回覆 407 與 Basic 挑戰。
func writeProxyAuthRequired(conn net.Conn) {
	resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"multi-cf-proxy\"\r\n" +
		"Content-Length: 0\r\nConnection: close\r\n\r\n"
	conn.Write([]byte(resp))
}

// parseProxyAuth 解析 Proxy-Authorization: Basic base64(user:pass)。
func parseProxyAuth(h string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}

// tunnel 處理 CONNECT：建立隧道後雙向轉發。
func (h *HTTP) tunnel(conn net.Conn, br *bufio.Reader, user, pass string, req *http.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remote, _, err := h.svc.Route(ctx, user, pass, "tcp", req.URL.Host)
	if err != nil {
		writeRawResponse(conn, http.StatusBadGateway, "上游連線失敗")
		return
	}
	defer remote.Close()

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	// bufio.Reader 內可能已緩衝客戶端在 CONNECT 後發送的資料，需先轉發
	if n := br.Buffered(); n > 0 {
		if b, err := br.Peek(n); err == nil {
			remote.Write(b)
		}
	}
	transfer(conn, remote)
}

// forward 轉發普通 HTTP 請求（absolute-URI → origin-form）。
func (h *HTTP) forward(conn net.Conn, br *bufio.Reader, req *http.Request, user, pass string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		if req.TLS == nil || req.URL.Scheme == "http" {
			host = net.JoinHostPort(host, "80")
		} else {
			host = net.JoinHostPort(host, "443")
		}
	}
	remote, _, err := h.svc.Route(ctx, user, pass, "tcp", host)
	if err != nil {
		writeRawResponse(conn, http.StatusBadGateway, "上游連線失敗")
		return err
	}
	defer remote.Close()
	remote.SetDeadline(time.Now().Add(90 * time.Second))

	outReq := req.Clone(ctx)
	outReq.RequestURI = "" // client 側欄位，寫出前必須清空
	outReq.URL.Scheme = ""
	outReq.URL.Host = ""
	outReq.Host = req.URL.Host
	outReq.Header.Del("Proxy-Authorization")
	for _, h_ := range hopHeaders {
		outReq.Header.Del(h_)
	}
	if err := outReq.Write(remote); err != nil {
		writeRawResponse(conn, http.StatusBadGateway, "寫入上游失敗")
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(remote), req)
	if err != nil {
		writeRawResponse(conn, http.StatusBadGateway, "讀取上游回應失敗")
		return err
	}
	defer resp.Body.Close()
	for _, h_ := range hopHeaders {
		resp.Header.Del(h_)
	}
	if err := resp.Write(conn); err != nil {
		return err
	}
	// 保持 keep-alive 循環
	return nil
}

// writeRawResponse 寫極簡回應。
func writeRawResponse(conn net.Conn, code int, msg string) {
	status := http.StatusText(code)
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, status, len(msg), msg)
}
