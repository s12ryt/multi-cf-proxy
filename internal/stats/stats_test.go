package stats

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestEmptySnapshot(t *testing.T) {
	s := NewCollector()
	snap := s.Snapshot()
	if len(snap.Upstreams) != 0 || len(snap.Accounts) != 0 {
		t.Errorf("空收集器快照應為空: %+v", snap)
	}
}

// fakeConn 測試輔助：可指定遠端位址的假連線。
type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeConn struct {
	remoteAddr net.Addr
}

func (c *fakeConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (c *fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return fakeAddr("127.0.0.1:0") }
func (c *fakeConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func writeN(t *testing.T, s *Collector, addr, upstream, account string, n int) {
	t.Helper()
	w := s.WrapConn(&fakeConn{remoteAddr: fakeAddr(addr)}, upstream, account)
	if _, err := w.Write(make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamTrafficByIPFamily(t *testing.T) {
	s := NewCollector()
	writeN(t, s, "1.2.3.4:443", "u1", "alice", 1000)
	writeN(t, s, "[2606:4700::1]:443", "u1", "alice", 200)

	snap := s.Snapshot()
	up, ok := snap.Upstreams["u1"]
	if !ok {
		t.Fatal("快照缺少 u1")
	}
	if up.UpBytes != 1000 {
		t.Errorf("u1 v4 上行 = %d, want 1000", up.UpBytes)
	}
	if up.IPv6UpBytes != 200 {
		t.Errorf("u1 v6 上行 = %d, want 200", up.IPv6UpBytes)
	}
	if up.DownBytes != 0 || up.IPv6DownBytes != 0 {
		t.Errorf("未發生下行卻有計數: %+v", up)
	}
}

func TestAccountTraffic(t *testing.T) {
	s := NewCollector()
	s.AccountUp("alice", 10)
	s.AccountDown("alice", 20)
	s.AccountUp("alice", 5)

	snap := s.Snapshot()
	ac := snap.Accounts["alice"]
	if ac.UpBytes != 15 || ac.DownBytes != 20 {
		t.Errorf("alice = %d/%d, want 15/20", ac.UpBytes, ac.DownBytes)
	}
}

func TestWrapConnCountsByIPFamily(t *testing.T) {
	s := NewCollector()
	writeN(t, s, "1.2.3.4:443", "u1", "alice", 100)
	writeN(t, s, "[2606:4700::1]:443", "u2", "alice", 50)

	snap := s.Snapshot()
	if got := snap.Upstreams["u1"].UpBytes; got != 100 {
		t.Errorf("u1 UpBytes = %d, want 100", got)
	}
	if got := snap.Upstreams["u2"].IPv6UpBytes; got != 50 {
		t.Errorf("u2 IPv6UpBytes = %d, want 50", got)
	}
	if got := snap.Accounts["alice"].UpBytes; got != 150 {
		t.Errorf("alice UpBytes = %d, want 150", got)
	}
}

func TestLastActiveAndConnections(t *testing.T) {
	s := NewCollector()
	before := time.Now()
	w := s.WrapConn(&fakeConn{remoteAddr: fakeAddr("1.2.3.4:443")}, "u1", "alice")
	s.AccountUp("alice", 1)
	w.Close()

	snap := s.Snapshot()
	ac := snap.Accounts["alice"]
	if ac.Connections != 0 {
		t.Errorf("關閉後連接數 = %d, want 0", ac.Connections)
	}
	if ac.TotalConns != 1 {
		t.Errorf("累計連接 = %d, want 1", ac.TotalConns)
	}
	if ac.LastActive.Before(before) {
		t.Errorf("LastActive 未更新: %v", ac.LastActive)
	}
}

func TestDoubleCloseCountsOnce(t *testing.T) {
	s := NewCollector()
	w := s.WrapConn(&fakeConn{remoteAddr: fakeAddr("1.2.3.4:443")}, "u1", "alice")
	w.Close()
	w.Close()
	snap := s.Snapshot()
	if snap.Accounts["alice"].Connections != 0 {
		t.Errorf("重複 Close 不應重複扣減: %d", snap.Accounts["alice"].Connections)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := NewCollector()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				s.AccountUp("a", 1)
				s.AccountDown("a", 1)
				s.ConnOpen("a")
				s.ConnClose("a")
				_ = s.Snapshot()
			}
		}()
	}
	wg.Wait()
	snap := s.Snapshot()
	if got := snap.Accounts["a"].UpBytes; got != 16000 {
		t.Errorf("併發上行計數遺失: %d, want 16000", got)
	}
	if got := snap.Accounts["a"].Connections; got != 0 {
		t.Errorf("併發後活躍連接應為 0: %d", got)
	}
}
