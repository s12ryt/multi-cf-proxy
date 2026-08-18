package web

import (
	"strings"
	"testing"
)

// TestIndexHTMLContract 前端交互契約：嵌入頁必須滿足的 UI/UX 硬性要求。
// 依據 ui-ux-pro-max 設計系統（Dark OLED、Fira 系、無外鏈依賴）與 UX 法則：
// 提交反饋(High)、空狀態引導(Medium)、表格溢出(Medium)、reduced-motion、鍵盤可達。
func TestIndexHTMLContract(t *testing.T) {
	raw, err := Static.ReadFile("index.html")
	if err != nil {
		t.Fatalf("讀取嵌入頁失敗: %v", err)
	}
	html := string(raw)

	mustContain := []struct {
		desc, substr string
	}{
		{"帳密展示用自繪 modal（非阻塞、可複製）", `id="modal"`},
		{"toast 有 aria-live 無障礙播報", `aria-live`},
		{"尊重 prefers-reduced-motion", "prefers-reduced-motion"},
		{"頁面不可見時暫停輪詢", "visibilitychange"},
		{"表格小屏橫向滾動", "overflow-x"},
		{"空狀態引導（無上游時）", "empty-state"},
		{"按鈕請求中 loading 態", "loading"},
		{"複製到剪貼板功能", "clipboard"},
		{"鍵盤 Esc 關閉彈窗", "Escape"},
		{"SVG 圖標而非 emoji 圖標", "<svg"},
		{"系統字體棧（無外鏈字體依賴）", "font-family:system-ui"},
		{"內嵌 favicon（自足，無 404）", "rel=\"icon\""},
		// v1.4：一鍵複製代理連結 + 收合式按鈕
		{"複製 SOCKS 代理連結", "socks5h://"},
		{"複製 HTTP 代理連結", "http://"},
		{"上游表帳號欄含 SOCKS/HTTP 複製鈕", "data-link=\"socks\""},
		{"新增上游收合按鈕（註冊+導入合一）", "新增上游"},
		{"新增上游 modal 含自動/手動兩個分頁", "tab-btn"},
		{"設置收合按鈕（設置+改密碼合一）", "打開設置"},
		// v1.5：上游延遲觀察與可選的延遲丟棄門檻
		{"上游延遲毫秒值", "last_latency_ms"},
		{"延遲過高丟棄設置鍵", "latency_discard_seconds"},
		{"延遲過高丟棄設置輸入", "setLatency"},
		{"延遲欄位", "延遲"},
	}
	for _, m := range mustContain {
		if !strings.Contains(html, m.substr) {
			t.Errorf("缺少 %s：未找到 %q", m.desc, m.substr)
		}
	}

	mustNotContain := []struct {
		desc, substr string
	}{
		{"原生 alert（阻塞且可被誤關，帳密會丟失）", "alert("},
		{"原生 confirm（阻塞且樣式突兀）", "confirm("},
		{"外鏈字體（離線/VPS 環境不可達）", "fonts.googleapis"},
		{"外鏈 CDN 腳本（單檔自足原則）", "https://cdn"},
	}
	for _, m := range mustNotContain {
		if strings.Contains(html, m.substr) {
			t.Errorf("禁止 %s：發現 %q", m.desc, m.substr)
		}
	}
}
