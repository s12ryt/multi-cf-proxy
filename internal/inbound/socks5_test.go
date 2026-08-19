package inbound

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"multi-cf-proxy/internal/auth"
	"multi-cf-proxy/internal/config"
	"multi-cf-proxy/internal/dispatcher"
	"multi-cf-proxy/internal/stats"
	"multi-cf-proxy/internal/tunnel"
)

// ---- 測試基樁 ----

// echoTunnel 把所有流量導回測試 echo server 的隧道。
type echoTunnel struct {
	id     string
	target string // echo server addr
}

func (e *echoTunnel) ID() string                        { return e.id }
func (e *echoTunnel) Fingerprint() string               { return "" }
func (e *echoTunnel) Start(ctx context.Context) error   { return nil }
func (e *echoTunnel) Stop()                             {}
func (e *echoTunnel) Rebuild(ctx context.Context) error { return nil }
func (e *echoTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return net.Dial("tcp", e.target)
}

type echoRegistry struct {
	t *echoTunnel
}

func (r *echoRegistry) Bound(id string) (tunnel.Tunnel, bool) { return r.t, true }
func (r *echoRegistry) Healthy() []tunnel.Tunnel              { return []tunnel.Tunnel{r.t} }
func (r *echoRegistry) IsHealthy(id string) bool              { return true }
func (r *echoRegistry) HealthySortedByLatency() []tunnel.Tunnel {
	return []tunnel.Tunnel{r.t}
}

// startEcho 啟動 echo server，返回地址。
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func startServer(t *testing.T) (addr string, echoAddr string) {
	t.Helper()
	echoAddr = startEcho(t)
	up := &config.Upstream{ID: "u1", Enabled: true, Account: config.Account{Username: "warp-aaaa", Password: "pw1"}}
	svc := dispatcher.NewService(auth.NewStore([]*config.Upstream{up}), &echoRegistry{t: &echoTunnel{id: "u1", target: echoAddr}}, stats.NewCollector())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewSOCKS5(svc)
	go srv.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), echoAddr
}

// ---- SOCKS5 客戶端輔助 ----

func socksHandshake(t *testing.T, c net.Conn, user, pass string) error {
	t.Helper()
	// 方法協商：僅提出 0x02（帳密）
	c.Write([]byte{0x05, 0x01, 0x02})
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x02 {
		return fmt.Errorf("server 拒絕帳密方法: %v", buf)
	}
	// RFC1929 子協商
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	c.Write(req)
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("帳密被拒: %v", resp)
	}
	return nil
}

func socksConnect(t *testing.T, c net.Conn, atyp byte, addr []byte, port uint16) []byte {
	t.Helper()
	req := []byte{0x05, 0x01, 0x00, atyp}
	req = append(req, addr...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	req = append(req, p[:]...)
	c.Write(req)
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0x00 {
		return nil // 失敗，僅回傳 nil 由調用方檢查
	}
	// 跳過 BND.ADDR/PORT（此實作固定回 0.0.0.0:0，10 位元組）
	rest := make([]byte, 6)
	io.ReadFull(c, rest)
	return head
}

// ---- 測試 ----

func TestSOCKS5FullFlowDomain(t *testing.T) {
	addr, echoAddr := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := socksHandshake(t, c, "warp-aaaa", "pw1"); err != nil {
		t.Fatalf("handshake 失敗: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(echoAddr)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	if socksConnect(t, c, 0x03, append([]byte{byte(len(host))}, []byte(host)...), port) == nil {
		t.Fatal("CONNECT 應成功")
	}

	c.Write([]byte("hello socks"))
	buf := make([]byte, 11)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("echo 讀取失敗: %v", err)
	}
	if string(buf) != "hello socks" {
		t.Errorf("echo 內容 = %q", buf)
	}
}

func TestSOCKS5IPv4Address(t *testing.T) {
	addr, echoAddr := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := socksHandshake(t, c, "warp-aaaa", "pw1"); err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(echoAddr)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	ip := net.ParseIP(host).To4()
	if socksConnect(t, c, 0x01, ip, port) == nil {
		t.Fatal("IPv4 CONNECT 應成功")
	}
}

func TestSOCKS5RejectWrongPassword(t *testing.T) {
	addr, _ := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := socksHandshake(t, c, "warp-aaaa", "wrong"); err == nil {
		t.Fatal("錯誤密碼應被拒")
	}
}

func TestSOCKS5RejectNoAuthMethod(t *testing.T) {
	addr, _ := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.Write([]byte{0x05, 0x01, 0x00}) // 僅提出無認證
	buf := make([]byte, 2)
	io.ReadFull(c, buf)
	if buf[1] != 0xFF {
		t.Errorf("無認證方法應被拒（0xFF）, got %v", buf)
	}
}

func TestSOCKS5RejectUDPCommand(t *testing.T) {
	addr, echoAddr := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := socksHandshake(t, c, "warp-aaaa", "pw1"); err != nil {
		t.Fatal(err)
	}
	_ = echoAddr
	host := []byte{0x7f, 0, 0, 1}
	var port uint16 = 53
	req := []byte{0x05, 0x03, 0x00, 0x01} // CMD=UDP
	req = append(req, host...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	req = append(req, p[:]...)
	c.Write(req)
	resp := make([]byte, 4)
	io.ReadFull(c, resp)
	if resp[1] != 0x07 {
		t.Errorf("UDP 應回 CMD NOT SUPPORTED(0x07), got %#x", resp[1])
	}
}

func TestSOCKS5RejectBadVersion(t *testing.T) {
	addr, _ := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.Write([]byte{0x04, 0x01, 0x02}) // SOCKS4 版本號
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err == nil {
		t.Fatalf("非法版本應斷開或拒絕, got %v", buf)
	}
}
