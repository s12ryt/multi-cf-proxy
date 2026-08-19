// Package listen 熱重載監聽伺服器：端口變更時先綁新 listener、成功後關舊。
package listen

import (
	"errors"
	"net"
	"testing"
	"time"
)

// freePort 取一個當前空閒的本地端口（尽力而为）。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取得空閒端口失敗: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// echoServe 接受連線即關（僅供驗證 accept 可達）。
func echoServe(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		conn.Close()
	}
}

// canDial 驗證端口可連通。
func canDial(t *testing.T, port int) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(port)), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestStartAndAccept(t *testing.T) {
	s := New()
	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	if err := s.Start("t", addr, echoServe); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !canDial(t, port) {
		t.Error("初始啟動後端口應可連通")
	}
}

func TestSwapSameAddrIsNoop(t *testing.T) {
	s := New()
	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	if err := s.Start("t", addr, echoServe); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Swap("t", addr); err != nil {
		t.Fatalf("同址 Swap 應為 no-op 成功: %v", err)
	}
	// 舊 listener 未被替換：端口持續可連通
	if !canDial(t, port) {
		t.Error("同址 Swap 不應中斷既有監聽")
	}
}

func TestSwapToNewAddr(t *testing.T) {
	s := New()
	oldPort := freePort(t)
	newPort := freePort(t)
	if err := s.Start("t", net.JoinHostPort("127.0.0.1", itoa(oldPort)), echoServe); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Swap("t", net.JoinHostPort("127.0.0.1", itoa(newPort))); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	if !canDial(t, newPort) {
		t.Error("Swap 後新端口應可連通")
	}
	if canDial(t, oldPort) {
		t.Error("Swap 後舊端口應已關閉")
	}
}

func TestSwapBindFailureKeepsOld(t *testing.T) {
	s := New()
	oldPort := freePort(t)
	if err := s.Start("t", net.JoinHostPort("127.0.0.1", itoa(oldPort)), echoServe); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// 佔住一個端口使新綁定失敗
	blocker, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", itoa(freePort(t))))
	if err != nil {
		t.Fatalf("佔用端口失敗: %v", err)
	}
	defer blocker.Close()
	badAddr := blocker.Addr().String()

	if err := s.Swap("t", badAddr); err == nil {
		t.Fatal("綁定失敗的 Swap 應返回錯誤")
	}
	if !canDial(t, oldPort) {
		t.Error("綁定失敗後舊 listener 應保留可用")
	}
}

func TestServeErrorReported(t *testing.T) {
	s := New()
	port := freePort(t)
	boom := errors.New("boom")
	if err := s.Start("t", net.JoinHostPort("127.0.0.1", itoa(port)), func(net.Listener) error {
		return boom
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case err := <-s.ErrCh():
		if !errors.Is(err, boom) {
			t.Errorf("ErrCh 應包含原始錯誤, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("未收到 serve 錯誤")
	}
}

func TestSwapClosesOldQuietly(t *testing.T) {
	s := New()
	oldPort := freePort(t)
	newPort := freePort(t)
	if err := s.Start("t", net.JoinHostPort("127.0.0.1", itoa(oldPort)), echoServe); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Swap("t", net.JoinHostPort("127.0.0.1", itoa(newPort))); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	// 舊 listener 關閉導致 Accept 返回 ErrClosed——不應進 ErrCh
	select {
	case err := <-s.ErrCh():
		t.Errorf("被替換 listener 的關閉錯誤不應上報: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if !canDial(t, newPort) {
		t.Error("Swap 後新端口應可連通")
	}
}
