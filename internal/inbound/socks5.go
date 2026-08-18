// Package inbound 提供入站代理服務：SOCKS5（RFC 1928/1929）與 HTTP。
package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"multi-cf-proxy/internal/dispatcher"
)

// SOCKS5 回覆碼（RFC 1928 第 6 節）。
const (
	repSucceeded        = 0x00
	repGeneralFailure   = 0x01
	repConnRefused      = 0x05
	repCmdNotSupported  = 0x07
	repAtypNotSupported = 0x08
)

const (
	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF
	cmdConnect         = 0x01
	cmdUDP             = 0x03
)

// SOCKS5 入站服務器。
type SOCKS5 struct {
	svc *dispatcher.Service
	wg  sync.WaitGroup
}

// NewSOCKS5 建立 SOCKS5 服務；鑑權與撥號經 dispatcher。
func NewSOCKS5(svc *dispatcher.Service) *SOCKS5 {
	return &SOCKS5{svc: svc}
}

// Serve 接受並處理連線，直到 listener 關閉。
func (s *SOCKS5) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

// Stop 等待全部活躍連線結束。
func (s *SOCKS5) Stop() { s.wg.Wait() }

func (s *SOCKS5) handle(conn net.Conn) {
	defer conn.Close()
	if err := s.serve(conn); err != nil {
		// 常見的客戶端斷開不記日誌（靜默），其他錯誤供上層觀測
		_ = err
	}
}

func (s *SOCKS5) serve(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("不支援的 SOCKS 版本 %#x", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	hasUserPass := false
	for _, m := range methods {
		if m == methodUserPass {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		conn.Write([]byte{0x05, methodNoAcceptable})
		return errors.New("客戶端未提供帳密方法")
	}
	if _, err := conn.Write([]byte{0x05, methodUserPass}); err != nil {
		return err
	}

	username, password, err := readUserPass(conn)
	if err != nil {
		return err
	}
	if !s.svc.Authenticate(username, password) {
		conn.Write([]byte{0x01, 0x01}) // RFC1929: 失敗
		return dispatcher.ErrAuth
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}

	req, err := readRequest(conn)
	if err != nil {
		return err
	}
	if req.cmd == cmdUDP {
		writeReply(conn, repCmdNotSupported)
		return errors.New("不支援 UDP ASSOCIATE")
	}
	if req.cmd != cmdConnect {
		writeReply(conn, repCmdNotSupported)
		return fmt.Errorf("不支援的命令 %#x", req.cmd)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remote, _, err := s.svc.Route(ctx, username, password, "tcp", req.addr)
	if err != nil {
		if errors.Is(err, dispatcher.ErrNoHealthyUpstream) {
			writeReply(conn, repGeneralFailure)
		} else {
			writeReply(conn, repConnRefused)
		}
		return err
	}
	defer remote.Close()

	writeReply(conn, repSucceeded)
	transfer(conn, remote)
	return nil
}

// readUserPass 讀取 RFC1929 帳密子協商。
func readUserPass(conn net.Conn) (string, string, error) {
	ver := make([]byte, 1)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return "", "", err
	}
	if ver[0] != 0x01 {
		return "", "", fmt.Errorf("RFC1929 版本不符 %#x", ver[0])
	}
	ulen := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulen); err != nil {
		return "", "", err
	}
	user := make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, user); err != nil {
		return "", "", err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return "", "", err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return "", "", err
	}
	return string(user), string(pass), nil
}

type socksRequest struct {
	cmd  byte
	addr string // host:port
}

// readRequest 讀取 CONNECT/UDP 請求（僅解析，不校驗 cmd）。
func readRequest(conn net.Conn) (*socksRequest, error) {
	hdr := make([]byte, 4) // VER CMD RSV ATYP
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x05 {
		return nil, fmt.Errorf("請求版本不符 %#x", hdr[0])
	}
	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case 0x03: // 域名
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	default:
		return nil, fmt.Errorf("不支援的 ATYP %#x", hdr[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return &socksRequest{cmd: hdr[1], addr: net.JoinHostPort(host, strconv.Itoa(int(port)))}, nil
}

func writeReply(conn net.Conn, rep byte) {
	// VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// pastDeadline 已過去的時刻，用於解除另一方向 io.Copy 的阻塞。
func pastDeadline() time.Time { return time.Unix(1, 0) }

// transfer 雙向轉發直到任一方向結束。
func transfer(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(a, b)
		a.SetDeadline(pastDeadline())
		done <- struct{}{}
	}()
	go func() {
		io.Copy(b, a)
		b.SetDeadline(pastDeadline())
		done <- struct{}{}
	}()
	<-done
	<-done
}
