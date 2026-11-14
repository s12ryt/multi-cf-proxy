// 覆蓋 R5：DNS 快取與撥號目標解析的熱路徑契約。
// 行 16 快取存已解析位址（命中不得重新解析字串）；行 44 重複入快取不得膨脹順序表；行 66 基準。
package tunnel

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func fixedResolver(ips ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return ips, nil }
}

// TestResolveTargetCacheHitZeroParse 快取命中時只配置候選切片本身：
// 位址在入快取時已解析為 netip.Addr，不應逐條連線重新解析字串。
func TestResolveTargetCacheHitZeroParse(t *testing.T) {
	c := newDNSCache(time.Minute, 16, fixedResolver("1.2.3.4", "5.6.7.8"))
	ctx := context.Background()
	if _, err := resolveTarget(ctx, c, "example.com:443"); err != nil {
		t.Fatal(err)
	}

	n := testing.AllocsPerRun(200, func() {
		if _, err := resolveTarget(ctx, c, "example.com:443"); err != nil {
			t.Fatal(err)
		}
	})
	if n > 1 {
		t.Errorf("快取命中路徑配置 %v 次（應僅候選切片 1 次）", n)
	}
}

// TestDNSCacheStoresParsedAddrs 快取介面直接交付已解析位址。
func TestDNSCacheStoresParsedAddrs(t *testing.T) {
	c := newDNSCache(time.Minute, 16, fixedResolver("1.2.3.4", "bad-ip", "::1"))
	got, err := c.resolveHost(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("::1")}
	if len(got) != len(want) {
		t.Fatalf("應過濾無效位址並回傳 %d 筆: %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("位址[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestDNSCacheOrderStaysBounded 同一域名反覆刷新不得讓順序表無限增長。
func TestDNSCacheOrderStaysBounded(t *testing.T) {
	c := newDNSCache(time.Nanosecond, 16, fixedResolver("1.2.3.4"))
	for i := 0; i < 50; i++ {
		if _, err := c.resolveHost(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	n := len(c.order)
	c.mu.Unlock()
	if n != 1 {
		t.Errorf("順序表長度 = %d（同域名重複入快取未去重）", n)
	}
}

// TestDNSCacheSetTTLConcurrent setTTL 與解析併發不得競爭（-race 下驗證）。
func TestDNSCacheSetTTLConcurrent(t *testing.T) {
	c := newDNSCache(time.Minute, 16, fixedResolver("1.2.3.4"))
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			c.setTTL(time.Duration(i%2) * time.Minute)
		}
		close(done)
	}()
	for i := 0; i < 500; i++ {
		c.resolveHost(context.Background(), "example.com")
	}
	<-done
}

func BenchmarkResolveTargetCacheHit(b *testing.B) {
	c := newDNSCache(time.Minute, 16, fixedResolver("1.2.3.4", "5.6.7.8"))
	ctx := context.Background()
	resolveTarget(ctx, c, "example.com:443")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resolveTarget(ctx, c, "example.com:443")
	}
}

func BenchmarkResolveTargetIPLiteral(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resolveTarget(ctx, nil, "1.1.1.1:443")
	}
}
