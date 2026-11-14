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

// maxAddrLen 握手中任一可變欄位的上限（域名/帳號/密碼皆為單位元組長度前綴）。
const maxAddrLen = 255

// 固定回覆字節串：握手路徑逐條連線各寫一次，不應每次新配置切片。
var (
	replyNoAcceptable = []byte{0x05, methodNoAcceptable}
	replyUserPass     = []byte{0x05, methodUserPass}
	replyAuthFail     = []byte{0x01, 0x01}
	replyAuthOK       = []byte{0x01, 0x00}
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
	// 單一 scratch 緩衝貫穿整段握手：方法列表、帳密、請求位址都最多 255 位元組，
	// 原本每個欄位各 make 一次（一條連線近十次小配置）。
	var scratch [maxAddrLen]byte
	buf := scratch[:]

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("不支援的 SOCKS 版本 %#x", buf[0])
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return err
	}
	hasUserPass := false
	for _, m := range buf[:nMethods] {
		if m == methodUserPass {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		conn.Write(replyNoAcceptable)
		return errors.New("客戶端未提供帳密方法")
	}
	if _, err := conn.Write(replyUserPass); err != nil {
		return err
	}

	username, password, err := readUserPass(conn, buf)
	if err != nil {
		return err
	}
	if !s.svc.Authenticate(username, password) {
		conn.Write(replyAuthFail) // RFC1929: 失敗
		return dispatcher.ErrAuth
	}
	if _, err := conn.Write(replyAuthOK); err != nil {
		return err
	}

	req, err := readRequest(conn, buf)
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

// readUserPass 讀取 RFC1929 帳密子協商；buf 為呼叫方提供的 scratch（≥255 位元組）。
func readUserPass(r io.Reader, buf []byte) (string, string, error) {
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return "", "", err
	}
	if buf[0] != 0x01 {
		return "", "", fmt.Errorf("RFC1929 版本不符 %#x", buf[0])
	}
	ulen := int(buf[1])
	if _, err := io.ReadFull(r, buf[:ulen]); err != nil {
		return "", "", err
	}
	user := string(buf[:ulen])
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return "", "", err
	}
	plen := int(buf[0])
	if _, err := io.ReadFull(r, buf[:plen]); err != nil {
		return "", "", err
	}
	return user, string(buf[:plen]), nil
}

type socksRequest struct {
	cmd  byte
	addr string // host:port
}

// readRequest 讀取 CONNECT/UDP 請求（僅解析，不校驗 cmd）；buf 為 scratch（≥255 位元組）。
func readRequest(r io.Reader, buf []byte) (socksRequest, error) {
	if _, err := io.ReadFull(r, buf[:4]); err != nil { // VER CMD RSV ATYP
		return socksRequest{}, err
	}
	if buf[0] != 0x05 {
		return socksRequest{}, fmt.Errorf("請求版本不符 %#x", buf[0])
	}
	cmd, atyp := buf[1], buf[3]
	var host string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			return socksRequest{}, err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // 域名
		if _, err := io.ReadFull(r, buf[:1]); err != nil {
			return socksRequest{}, err
		}
		l := int(buf[0])
		if _, err := io.ReadFull(r, buf[:l]); err != nil {
			return socksRequest{}, err
		}
		host = string(buf[:l])
	case 0x04: // IPv6
		if _, err := io.ReadFull(r, buf[:16]); err != nil {
			return socksRequest{}, err
		}
		host = net.IP(buf[:16]).String()
	default:
		return socksRequest{}, fmt.Errorf("不支援的 ATYP %#x", atyp)
	}
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return socksRequest{}, err
	}
	port := binary.BigEndian.Uint16(buf[:2])
	return socksRequest{cmd: cmd, addr: net.JoinHostPort(host, strconv.Itoa(int(port)))}, nil
}

// replySucceeded 等固定回覆：VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0。
var replyTemplate = [10]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

func writeReply(conn net.Conn, rep byte) {
	r := replyTemplate
	r[1] = rep
	conn.Write(r[:])
}
