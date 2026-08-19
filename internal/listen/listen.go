// Package listen 熱重載監聽伺服器：端口變更時先綁新 listener、成功後關舊，
// 綁定失敗保留舊 listener 不中斷服務。
package listen

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// entry 單個服務的當前監聽狀態。
type entry struct {
	addr  string
	ln    net.Listener
	serve func(net.Listener) error
}

// Server 管理多個具名監聽服務，支持端口熱替換。
type Server struct {
	mu      sync.Mutex
	entries map[string]*entry
	errCh   chan error
}

// New 建立監聽伺服器。
func New() *Server {
	return &Server{
		entries: map[string]*entry{},
		errCh:   make(chan error, 8),
	}
}

// ErrCh 返回服務異常退出通道（僅未被替換的 listener 的真實錯誤會進入）。
func (s *Server) ErrCh() <-chan error { return s.errCh }

// Start 初始啟動一個具名服務；失敗返回錯誤（調用方決定是否致命）。
func (s *Server) Start(name, addr string, serve func(net.Listener) error) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("監聽 %s（%s）失敗: %w", name, addr, err)
	}
	s.mu.Lock()
	s.entries[name] = &entry{addr: addr, ln: ln, serve: serve}
	s.mu.Unlock()
	go s.serveLoop(name, ln, serve)
	return nil
}

// Swap 熱替換端口：地址相同為 no-op；先綁新 listener（失敗則保留舊並返回錯誤），
// 成功後更新登記並關閉舊 listener（僅停止 accept，既有連線自然收尾）。
func (s *Server) Swap(name, newAddr string) error {
	s.mu.Lock()
	e, ok := s.entries[name]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("未知服務 %s", name)
	}
	oldAddr := e.addr
	if oldAddr == newAddr {
		s.mu.Unlock()
		return nil // 同址 no-op，不打斷任何連線
	}
	s.mu.Unlock()

	// 鎖外綁新：失敗直接返回，舊 listener 原封不動
	ln, err := net.Listen("tcp", newAddr)
	if err != nil {
		return fmt.Errorf("綁定 %s（%s）失敗（沿用舊地址 %s）: %w", name, newAddr, oldAddr, err)
	}
	return s.commitSwap(name, oldAddr, newAddr, ln)
}

// commitSwap Swap 的提交階段：鎖內複查登記地址仍為出發時所見（防併發雙換）。
// 衝突時關閉自己綁的 listener（不留孤兒端口/洩漏 serveLoop）並返回錯誤。
func (s *Server) commitSwap(name, expectAddr, newAddr string, ln net.Listener) error {
	s.mu.Lock()
	e, ok := s.entries[name]
	if !ok {
		s.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("服務 %s 已被移除，放棄本次切換到 %s", name, newAddr)
	}
	if e.addr != expectAddr {
		s.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("服務 %s 已被併發替換（%s → %s），放棄本次切換到 %s", name, expectAddr, e.addr, newAddr)
	}
	serve := e.serve
	old := e.ln
	e.addr = newAddr
	e.ln = ln
	s.mu.Unlock()

	// 先登記新 listener 再關舊：serveLoop 以「listener 是否仍為當前登記」判斷過期
	go s.serveLoop(name, ln, serve)
	_ = old.Close()
	return nil
}

// serveLoop 運行 serve 並上報錯誤；被替換（Swap）或正常關閉的錯誤不上報。
func (s *Server) serveLoop(name string, ln net.Listener, serve func(net.Listener) error) {
	err := serve(ln)
	if err == nil || errors.Is(err, net.ErrClosed) {
		return
	}
	s.mu.Lock()
	e := s.entries[name]
	stale := e == nil || e.ln != ln
	s.mu.Unlock()
	if stale {
		return
	}
	select {
	case s.errCh <- fmt.Errorf("%s: %w", name, err):
	default:
	}
}
