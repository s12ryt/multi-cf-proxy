// 覆蓋 R4：轉發與握手的配置預算。
// 行 18 轉發緩衝複用（每條連線不得各自配置 32KiB）；行 60 SOCKS5 請求解析配置上限。
package inbound

import (
	"bytes"
	"io"
	"net"
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
// 直接量「池新建次數」而非進程配置量——後者在 -race 下混入檢測器自身開銷。
func TestTransferBufferReuse(t *testing.T) {
	payload := []byte("hello relay")
	for i := 0; i < 3; i++ {
		relayOnce(t, payload) // 預熱：填滿雙方向所需的緩衝
	}

	base := relayBufNew.Load()
	const runs = 20
	for i := 0; i < runs; i++ {
		relayOnce(t, payload)
	}
	// 一次轉發同時用兩個緩衝，留少量裕度給 P 本地池遷移；
	// 未複用時每輪必新建 2 個（≥40）。
	if grown := relayBufNew.Load() - base; grown > 4 {
		t.Errorf("%d 次轉發新建 %d 個緩衝（未複用）", runs, grown)
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
