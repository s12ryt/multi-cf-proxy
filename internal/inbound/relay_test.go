// 覆蓋 R4：轉發與握手的配置預算。
// 行 14 中繼緩衝歸還池中；行 40 雙向轉發收斂；行 66 SOCKS5 請求解析配置上限。
package inbound

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// TestRelayBufferReturnedToPool 中繼緩衝必須歸還池中：
// 每條連線各配置兩個 32KiB 緩衝會讓 GC 壓力隨併發線性上升。
// 用池語意驗證（歸還後立刻取回同一底層陣列），不用全程統計——
// 新建次數會被 GC 清空池干擾，-race 下尤甚。
func TestRelayBufferReturnedToPool(t *testing.T) {
	first := bufPool.Get().(*[]byte)
	if len(*first) != relayBufSize {
		t.Fatalf("緩衝大小 = %d, want %d", len(*first), relayBufSize)
	}
	bufPool.Put(first)
	if again := bufPool.Get().(*[]byte); again != first {
		t.Error("歸還後未取回同一緩衝（池未生效）")
	} else {
		bufPool.Put(again)
	}

	// copyBuffered 必須把借用的緩衝還回去：連續兩次只能新建一個。
	base := relayBufNew.Load()
	copyBuffered(io.Discard, bytes.NewReader([]byte("payload")))
	copyBuffered(io.Discard, bytes.NewReader([]byte("payload")))
	if grown := relayBufNew.Load() - base; grown > 1 {
		t.Errorf("兩次複製新建 %d 個緩衝（未歸還）", grown)
	}
}

// TestTransferMovesBothDirections 雙向轉發在任一端關閉後收斂。
func TestTransferMovesBothDirections(t *testing.T) {
	payload := []byte("hello relay")
	got := make(chan []byte, 1)

	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	go func() {
		s1.Write(payload)
		s1.Close()
	}()
	go func() {
		b, _ := io.ReadAll(s2)
		got <- b
		s2.Close()
	}()
	transfer(c1, c2)
	c1.Close()
	c2.Close()

	if b := <-got; string(b) != string(payload) {
		t.Errorf("上游側收到 %q, want %q", b, payload)
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
