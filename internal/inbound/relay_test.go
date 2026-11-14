// 覆蓋 R4：轉發與握手的配置預算。
// 行 18 轉發緩衝複用（每條連線不得各自配置 32KiB）；行 60 SOCKS5 請求解析配置上限。
package inbound

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"testing"
)

// relayOnce 跑一次完整雙向轉發（客戶端寫入後關閉，上游側吞掉資料）。
func relayOnce(t *testing.T, payload []byte) {
	t.Helper()
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	go func() {
		s1.Write(payload)
		s1.Close()
	}()
	go func() {
		io.ReadAll(s2)
		s2.Close()
	}()
	transfer(c1, c2)
	c1.Close()
	c2.Close()
}

// TestTransferBufferReuse 轉發緩衝必須取自共用池：
// 每條連線各配置兩個 32KiB 緩衝會讓 GC 壓力隨併發線性上升。
func TestTransferBufferReuse(t *testing.T) {
	payload := []byte("hello relay")
	relayOnce(t, payload) // 預熱：首次填池

	const runs = 20
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	for i := 0; i < runs; i++ {
		relayOnce(t, payload)
	}
	runtime.ReadMemStats(&m2)

	per := (m2.TotalAlloc - m1.TotalAlloc) / runs
	if per > 16*1024 {
		t.Errorf("每次轉發配置 %d 位元組（超過 16KiB，緩衝未複用）", per)
	}
}

// TestSOCKS5RequestAllocBudget 請求解析只應產生位址字串本身的配置。
func TestSOCKS5RequestAllocBudget(t *testing.T) {
	req := []byte{0x05, cmdConnect, 0x00, 0x03, 11}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xBB)

	var scratch [maxAddrLen]byte
	rd := bytes.NewReader(nil)
	n := testing.AllocsPerRun(100, func() {
		rd.Reset(req)
		if _, err := readRequest(rd, scratch[:]); err != nil {
			t.Fatal(err)
		}
	})
	// 僅剩 host 字串與 JoinHostPort 結果；舊版每欄位各自 make 會明顯超標。
	if n > 3 {
		t.Errorf("readRequest 路徑配置 %v 次（scratch 緩衝未生效）", n)
	}
}

func BenchmarkReadRequest(b *testing.B) {
	req := []byte{0x05, cmdConnect, 0x00, 0x03, 11}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xBB)
	var scratch [maxAddrLen]byte
	rd := bytes.NewReader(nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rd.Reset(req)
		readRequest(rd, scratch[:])
	}
}
