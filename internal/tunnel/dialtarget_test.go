package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"multi-cf-proxy/internal/config"
)

// resolveTarget：DialContext 的地址決策層（可單測的純邏輯）。
// IP 字面值直連不查快取；域名經 dnsCache（TTL 內免 DNS 往返）。

func TestResolveTargetLiteral(t *testing.T) {
	resolve, calls := fakeResolve([]string{"9.9.9.9"})
	c := newDNSCache(time.Minute, 8, resolve)
	for _, addr := range []string{"1.2.3.4:443", "[2606:4700::1]:80"} {
		aps, err := resolveTarget(context.Background(), c, addr)
		if err != nil {
			t.Fatalf("resolveTarget(%q) 失敗: %v", addr, err)
		}
		if len(aps) != 1 {
			t.Fatalf("字面值應恰一候選: %v", aps)
		}
		want, _ := netip.ParseAddrPort(addr)
		if aps[0] != want {
			t.Errorf("候選 = %v, want %v", aps[0], want)
		}
	}
	if *calls != 0 {
		t.Errorf("IP 字面值不應觸發解析, calls=%d", *calls)
	}
}

func TestResolveTargetHostnameCached(t *testing.T) {
	resolve, calls := fakeResolve([]string{"93.184.216.34", "93.184.216.35"})
	c := newDNSCache(time.Minute, 8, resolve)
	for i := 0; i < 2; i++ {
		aps, err := resolveTarget(context.Background(), c, "example.com:443")
		if err != nil {
			t.Fatal(err)
		}
		if len(aps) != 2 || aps[0].String() != "93.184.216.34:443" {
			t.Fatalf("候選不符: %v", aps)
		}
	}
	if *calls != 1 {
		t.Errorf("第二次應命中快取, calls=%d", *calls)
	}
}

func TestResolveTargetErrors(t *testing.T) {
	c := newDNSCache(time.Minute, 8, func(ctx context.Context, host string) ([]string, error) {
		return nil, errors.New("no such host")
	})
	if _, err := resolveTarget(context.Background(), c, "bad.test:443"); err == nil {
		t.Error("解析失敗應返回錯誤")
	}
	if _, err := resolveTarget(context.Background(), c, "example.com:0"); err == nil {
		t.Error("端口 0 應非法")
	}
	if _, err := resolveTarget(context.Background(), c, "example.com:70000"); err == nil {
		t.Error("端口超界應非法")
	}
	if _, err := resolveTarget(context.Background(), c, "no-port"); err == nil {
		t.Error("缺端口應非法")
	}
}

// TestSetDNSCacheTTLWireTunnel wireTunnel 的 TTL 設定直達快取。
func TestSetDNSCacheTTLWireTunnel(t *testing.T) {
	wt, err := WireFactory(&config.Upstream{
		ID: "u1", PrivateKey: base64KeyStr(1), PeerPublicKey: base64KeyStr(2),
		Endpoint: "engage.cloudflareclient.com:2408", Addresses: []string{"172.16.0.2/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := wt.(*wireTunnel)
	if err := w.SetDNSCacheTTL(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	w.dns.mu.Lock()
	ttl := w.dns.ttl
	w.dns.mu.Unlock()
	if ttl != 5*time.Second {
		t.Errorf("ttl = %v, want 5s", ttl)
	}
}

// TestManagerSetDNSCacheTTLPropagates Manager 設定 → 新建隧道收到 TTL。
func TestManagerSetDNSCacheTTLPropagates(t *testing.T) {
	var created []*fakeTunnel
	m := NewManager(fakeFactory(&created), nil, time.Hour, 3)
	if err := m.SetDNSCacheTTL(7 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background(), []*config.Upstream{mkUpstream("u1", true)}); err != nil {
		t.Fatal(err)
	}
	got := created[0].dnsTTL.Load().(time.Duration)
	if got != 7*time.Second {
		t.Errorf("新建隧道應收到 TTL 7s, got %v", got)
	}
}

// base64KeyStr 測試用 32 位元組金鑰的 base64。
func base64KeyStr(n int) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(n + i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// fakeTunnel 的 TTL 接收器（Manager 傳播測試用）。
func (f *fakeTunnel) SetDNSCacheTTL(d time.Duration) error {
	f.dnsTTL.Store(d)
	return nil
}
