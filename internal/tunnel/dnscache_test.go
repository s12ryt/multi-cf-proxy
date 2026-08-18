package tunnel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeResolve 計數型解析函數，固定返回 ips。
func fakeResolve(ips []string) (func(ctx context.Context, host string) ([]string, error), *int) {
	n := 0
	return func(ctx context.Context, host string) ([]string, error) {
		n++
		return ips, nil
	}, &n
}

func TestDNSCacheHitMiss(t *testing.T) {
	resolve, calls := fakeResolve([]string{"93.184.216.34"})
	c := newDNSCache(60*time.Second, 256, resolve)

	ips, err := c.resolveHost(context.Background(), "example.com")
	if err != nil || len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("首次解析失敗: %v %v", ips, err)
	}
	if *calls != 1 {
		t.Fatalf("首次應觸發解析, calls=%d", *calls)
	}
	// 命中：不再觸發解析
	for i := 0; i < 3; i++ {
		if _, err := c.resolveHost(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if *calls != 1 {
		t.Fatalf("TTL 內應命中快取, calls=%d", *calls)
	}
}

func TestDNSCacheTTLExpiry(t *testing.T) {
	resolve, calls := fakeResolve([]string{"1.1.1.1"})
	now := time.Now()
	c := newDNSCache(30*time.Second, 256, resolve)
	c.now = func() time.Time { return now }

	if _, err := c.resolveHost(context.Background(), "a.test"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second) // 過期
	if _, err := c.resolveHost(context.Background(), "a.test"); err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Fatalf("過期後應重新解析, calls=%d", *calls)
	}
}

func TestDNSCacheDisabled(t *testing.T) {
	resolve, calls := fakeResolve([]string{"1.1.1.1"})
	c := newDNSCache(0, 256, resolve) // TTL=0 停用：每次都解析
	for i := 0; i < 3; i++ {
		if _, err := c.resolveHost(context.Background(), "x.test"); err != nil {
			t.Fatal(err)
		}
	}
	if *calls != 3 {
		t.Fatalf("停用時每次都應解析, calls=%d", *calls)
	}
}

func TestDNSCacheCapacityEviction(t *testing.T) {
	resolve, _ := fakeResolve([]string{"1.1.1.1"})
	c := newDNSCache(60*time.Second, 2, resolve) // 容量 2
	for _, h := range []string{"a.test", "b.test", "c.test"} {
		if _, err := c.resolveHost(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) != 2 {
		t.Fatalf("容量應為 2, got %d", len(c.entries))
	}
	if _, ok := c.entries["a.test"]; ok {
		t.Error("最舊的 a.test 應被逐出")
	}
	if _, ok := c.entries["c.test"]; !ok {
		t.Error("最新的 c.test 應保留")
	}
}

func TestDNSCacheNegativeNotCached(t *testing.T) {
	n := 0
	resolve := func(ctx context.Context, host string) ([]string, error) {
		n++
		return nil, errors.New("no such host")
	}
	c := newDNSCache(60*time.Second, 256, resolve)
	for i := 0; i < 2; i++ {
		if _, err := c.resolveHost(context.Background(), "bad.test"); err == nil {
			t.Fatal("應返回解析錯誤")
		}
	}
	if n != 2 {
		t.Fatalf("負結果不應快取, calls=%d", n)
	}
	c.mu.Lock()
	len := len(c.entries)
	c.mu.Unlock()
	if len != 0 {
		t.Fatalf("負結果不應入快取, entries=%d", len)
	}
}

func TestDNSCacheConcurrent(t *testing.T) {
	resolve, _ := fakeResolve([]string{"1.1.1.1"})
	c := newDNSCache(60*time.Second, 256, resolve)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := c.resolveHost(context.Background(), "hot.test"); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
}
