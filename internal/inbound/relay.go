// 轉發層：雙向中繼與共用緩衝池。
// 行 20 緩衝池；行 32 copyBuffered（保留 splice 快路徑）；行 46 transfer 雙向中繼；行 62 bufio 讀取器池。
package inbound

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"
)

// relayBufSize 單方向中繼緩衝；與 io.Copy 默認值一致，對 TCP 吞吐足夠。
const relayBufSize = 32 * 1024

// bufPool 中繼緩衝池：每條代理連線兩個方向共 64KiB，
// 不複用時併發 1000 條即 64MiB 瞬時堆配置。
var bufPool = sync.Pool{New: func() any {
	b := make([]byte, relayBufSize)
	return &b
}}

// copyBuffered 以池化緩衝複製；dst/src 具備 ReadFrom/WriteTo 快路徑時由 io 直接走零拷貝。
func copyBuffered(dst io.Writer, src io.Reader) {
	bp := bufPool.Get().(*[]byte)
	io.CopyBuffer(dst, src, *bp)
	bufPool.Put(bp)
}

// pastDeadline 已過去的時刻，用於解除另一方向中繼的阻塞。
func pastDeadline() time.Time { return time.Unix(1, 0) }

// transfer 雙向轉發直到任一方向結束；
// 一個方向留在當前 goroutine，省一條 goroutine 與同步通道。
func transfer(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		copyBuffered(a, b)
		a.SetDeadline(pastDeadline())
	}()
	copyBuffered(b, a)
	b.SetDeadline(pastDeadline())
	wg.Wait()
}

// readerPool HTTP 請求/回應解析用的 bufio.Reader 池（每個 4KiB）。
var readerPool = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, 4096) }}

// getReader 取一個綁定到 r 的池化讀取器。
func getReader(r io.Reader) *bufio.Reader {
	br := readerPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

// putReader 歸還讀取器（解除來源引用，避免連線被池持有）。
func putReader(br *bufio.Reader) {
	br.Reset(nil)
	readerPool.Put(br)
}
