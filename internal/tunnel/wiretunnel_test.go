package tunnel

import (
	"context"
	"strings"
	"testing"

	"multi-cf-proxy/internal/config"
)

func validUpstream() *config.Upstream {
	// 一對語法合法的金鑰（內容隨機，僅驗證錯誤處理路徑，不會真正握手）。
	// endpoint 用字面 IP，避免測試依賴環境 DNS。
	return &config.Upstream{
		ID:            "u-test",
		Name:          "test",
		Enabled:       true,
		PrivateKey:    "yPvP7clDqhKvZwKMdtRgklcqZzZiK7xSGKz0rCN6gUQ=",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		Endpoint:      "127.0.0.1:2408",
		Addresses:     []string{"172.16.0.2/32"},
	}
}

func TestWireFactoryRejectsInvalidKeys(t *testing.T) {
	up := validUpstream()
	up.PrivateKey = "!!!invalid-base64!!!"
	tn, err := WireFactory(up)
	if err == nil {
		t.Fatal("非法私鑰應在建立時報錯")
	}
	if tn != nil {
		t.Error("失敗時不應返回隧道")
	}
	if !strings.Contains(err.Error(), "u-test") {
		t.Errorf("錯誤應包含隧道 ID: %v", err)
	}
}

func TestWireFactoryRejectsInvalidAddress(t *testing.T) {
	up := validUpstream()
	up.Addresses = []string{"not-an-ip/32"}
	if _, err := WireFactory(up); err == nil {
		t.Fatal("非法地址應報錯")
	}
}

func TestWireTunnelFingerprintAndStartStop(t *testing.T) {
	up := validUpstream()
	tn, err := WireFactory(up)
	if err != nil {
		t.Fatalf("合法配置應可建立: %v", err)
	}
	defer tn.Stop()

	if fp := tn.Fingerprint(); !strings.Contains(fp, up.PrivateKey) || !strings.Contains(fp, up.Endpoint) {
		t.Errorf("Fingerprint 應包含關鍵配置欄位: %q", fp)
	}
	// Start 應成功（僅本地建立，不等待握手）
	if err := tn.Start(context.Background()); err != nil {
		t.Fatalf("Start 失敗: %v", err)
	}
	// 重複 Stop 不應 panic
	tn.Stop()
	tn.Stop()
}

func TestWireTunnelDialAfterStopReturnsError(t *testing.T) {
	up := validUpstream()
	tn, err := WireFactory(up)
	if err != nil {
		t.Fatal(err)
	}
	tn.Start(context.Background())
	tn.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 500*1e6) // 500ms
	defer cancel()
	if _, err := tn.DialContext(ctx, "tcp", "1.1.1.1:80"); err == nil {
		t.Fatal("已停止的隧道撥號應報錯")
	}
}
