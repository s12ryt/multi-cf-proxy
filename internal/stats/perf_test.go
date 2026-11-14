// 覆蓋 R3：流量統計熱路徑的契約——每個封包不得取收集器映射鎖、不得配置。
// 行 12 I/O 不依賴 Collector.mu；行 50 Read/Write 零配置；行 70 基準。
package stats

import (
	"net"
	"testing"
	"time"
)

// TestConnIOIndependentOfCollectorLock 佔住映射鎖期間，連線讀寫仍須暢通：
// 包裝時已解析好計數器，每個封包只做原子加法。
func TestConnIOIndependentOfCollectorLock(t *testing.T) {
	c := NewCollector()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	wrapped := c.WrapConn(a, "u1", "alice")

	go func() {
		buf := make([]byte, 4)
		b.Read(buf)
		b.Write([]byte("pong"))
	}()

	c.mu.Lock()
	defer c.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		if _, err := wrapped.Write([]byte("ping")); err != nil {
			done <- err
			return
		}
		buf := make([]byte, 4)
		_, err := wrapped.Read(buf)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("讀寫失敗: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("I/O 熱路徑仍依賴收集器映射鎖（持鎖期間被阻塞）")
	}
}

// TestConnIOZeroAlloc 每個封包的統計不得配置記憶體。
func TestConnIOZeroAlloc(t *testing.T) {
	c := NewCollector()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
	wrapped := c.WrapConn(a, "u1", "alice")
	payload := []byte("0123456789")

	if n := testing.AllocsPerRun(200, func() { wrapped.Write(payload) }); n > 0 {
		t.Errorf("寫入路徑配置 %v 次（應為 0）", n)
	}
}

func BenchmarkCountingConnWrite(b *testing.B) {
	c := NewCollector()
	p1, p2 := net.Pipe()
	defer p1.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := p2.Read(buf); err != nil {
				return
			}
		}
	}()
	wrapped := c.WrapConn(p1, "u1", "alice")
	payload := []byte("0123456789")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		wrapped.Write(payload)
	}
}

// BenchmarkAcctViaMap / BenchmarkAcctDirect 對照每個封包的帳號計費路徑：
// 前者為優化前的實際路徑（取映射鎖 + 查找），後者為現行預解析計數器。
func BenchmarkAcctViaMap(b *testing.B) {
	c := NewCollector()
	b.ReportAllocs()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			c.AccountUp("alice", 10)
		}
	})
}

func BenchmarkAcctDirect(b *testing.B) {
	c := NewCollector()
	e := c.accountEntry("alice")
	b.ReportAllocs()
	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			e.up.Add(10)
			e.touch()
		}
	})
}

func BenchmarkWrapConn(b *testing.B) {
	c := NewCollector()
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.WrapConn(p1, "u1", "alice")
	}
}
