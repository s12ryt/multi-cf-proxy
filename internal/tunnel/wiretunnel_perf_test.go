// 覆蓋 R9：隧道撥號與裝置配置的熱路徑契約。
// 行 16 dns 快取指標免鎖（終身不變）；行 36 net 指標以原子取得；行 56 ipcConfig 基準。
package tunnel

import (
	"context"
	"strings"
	"testing"
	"time"

	"multi-cf-proxy/internal/config"
)

func wireFixture(t *testing.T) *wireTunnel {
	t.Helper()
	u := &config.Upstream{
		ID:            "u1",
		Name:          "warp",
		Enabled:       true,
		PrivateKey:    "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		PeerPublicKey: "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		Endpoint:      "162.159.192.1:2408",
		Addresses:     []string{"172.16.0.2/32", "fd01::5/128"},
	}
	tn, err := WireFactory(u)
	if err != nil {
		t.Fatal(err)
	}
	return tn.(*wireTunnel)
}

// TestDialContextNotRunningZeroLock 未運行時的快速失敗不得取互斥鎖：
// 撥號熱路徑與 Start/Stop 共用一把鎖，持鎖讀指標會與重建互相排隊。
func TestDialContextNotRunningZeroLock(t *testing.T) {
	w := wireFixture(t)
	w.mu.Lock() // 模擬重建中持鎖
	defer w.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := w.DialContext(context.Background(), "tcp", "1.1.1.1:443")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "未運行") {
			t.Fatalf("應快速回報未運行: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("撥號路徑仍在等待裝置鎖")
	}
}

// TestIPCConfigContainsPeerFields 配置字串包含必要欄位且端點為解析後位址。
func TestIPCConfigContainsPeerFields(t *testing.T) {
	w := wireFixture(t)
	w.resolvedEndpoint = "162.159.192.1:2408"
	got := w.ipcConfig()
	for _, want := range []string{
		"private_key=" + w.privateHex,
		"public_key=" + w.peerHex,
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"endpoint=162.159.192.1:2408",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("配置缺少 %q:\n%s", want, got)
		}
	}
}

func BenchmarkIPCConfig(b *testing.B) {
	w := wireFixture(&testing.T{})
	w.resolvedEndpoint = "162.159.192.1:2408"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = w.ipcConfig()
	}
}
