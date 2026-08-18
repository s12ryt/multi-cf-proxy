package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
)

// stubLookup 注入式 DNS 查詢（測試確定性）。
func stubLookup(ips []string, err error) funcRestore {
	orig := lookupHost
	lookupHost = func(host string) ([]string, error) { return ips, err }
	return funcRestore{fn: func() { lookupHost = orig }}
}

type funcRestore struct{ fn func() }

func (r funcRestore) restore() { r.fn() }

func TestResolveEndpointLiteralPassthrough(t *testing.T) {
	defer stubLookup(nil, errors.New("不應被調用")).restore()
	cases := []string{"127.0.0.1:2408", "[::1]:2408", "162.159.192.1:2408"}
	for _, ep := range cases {
		got, err := resolveEndpoint(ep)
		if err != nil || got != ep {
			t.Errorf("resolveEndpoint(%q) = %q, %v; want 原樣返回", ep, got, err)
		}
	}
}

func TestResolveEndpointHostname(t *testing.T) {
	restore := stubLookup([]string{"162.159.192.1", "162.159.192.5"}, nil)
	defer restore.restore()
	got, err := resolveEndpoint("engage.cloudflareclient.com:2408")
	if err != nil {
		t.Fatalf("resolveEndpoint 失敗: %v", err)
	}
	if got != "162.159.192.1:2408" {
		t.Errorf("解析結果 = %q, want 162.159.192.1:2408（取第一個 IP）", got)
	}
}

func TestResolveEndpointDNSFailure(t *testing.T) {
	restore := stubLookup(nil, errors.New("no such host"))
	defer restore.restore()
	_, err := resolveEndpoint("engage.cloudflareclient.com:2408")
	if err == nil {
		t.Fatal("DNS 失敗應返回錯誤")
	}
	if want := "engage.cloudflareclient.com"; !contains(err.Error(), want) {
		t.Errorf("錯誤應包含主機名 %q: %v", want, err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestResolveEndpointLocalhostReal 走真實解析器（hosts/DNS），驗證端口保留。
func TestResolveEndpointLocalhostReal(t *testing.T) {
	got, err := resolveEndpoint("localhost:2408")
	if err != nil {
		t.Fatalf("localhost 解析失敗: %v", err)
	}
	host, port, err := net.SplitHostPort(got)
	if err != nil || port != "2408" {
		t.Fatalf("端口應保留: %q, %v", got, err)
	}
	if net.ParseIP(host) == nil {
		t.Errorf("應解析為 IP 字面值, got %q", host)
	}
}

// TestWireTunnelStartResolvesHostname 端到端：域名 endpoint 的隧道可啟動
// （修復前：IPC error -22 ParseAddr("localhost") —— 與線上 bug 同類）。
func TestWireTunnelStartResolvesHostname(t *testing.T) {
	up := validUpstream()
	up.Endpoint = "localhost:2408"
	tn, err := WireFactory(up)
	if err != nil {
		t.Fatal(err)
	}
	defer tn.Stop()
	if err := tn.Start(context.Background()); err != nil {
		t.Fatalf("域名 endpoint 啟動應成功（先解析為 IP）: %v", err)
	}
}
