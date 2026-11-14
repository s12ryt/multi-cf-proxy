// 覆蓋 R6：管理面板的記憶體與回應編碼契約。
// 行 16 session 過期項惰性清理；行 44 JSON 回應單次寫出並帶 Content-Length；行 70 基準。
package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestValidSessionPurgesExpired 過期 token 在驗證時即移除：
// 原本只在登入時清理，長期運行會讓映射隨失效 token 無限增長。
func TestValidSessionPurgesExpired(t *testing.T) {
	s := &Server{sessions: map[string]time.Time{}}
	s.sessions["stale"] = time.Now().Add(-time.Minute)

	if s.validSession("stale") {
		t.Fatal("過期 session 不應通過驗證")
	}
	s.mu.Lock()
	_, still := s.sessions["stale"]
	s.mu.Unlock()
	if still {
		t.Error("過期 session 應於驗證時移除")
	}
}

// TestValidSessionKeepsLive 有效 token 不受清理影響。
func TestValidSessionKeepsLive(t *testing.T) {
	s := &Server{sessions: map[string]time.Time{}}
	tok := s.newSession()
	if !s.validSession(tok) {
		t.Fatal("新建 session 應有效")
	}
	s.mu.Lock()
	n := len(s.sessions)
	s.mu.Unlock()
	if n != 1 {
		t.Errorf("有效 session 數 = %d, want 1", n)
	}
}

// TestWriteJSONSetsContentLength 回應一次寫出：帶 Content-Length，非 chunked。
func TestWriteJSONSetsContentLength(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{"hello": "world"})

	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("狀態碼 = %d", res.StatusCode)
	}
	if got := res.Header.Get("Content-Length"); got == "" {
		t.Error("回應應帶 Content-Length（單次寫出）")
	}
	var out map[string]string
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["hello"] != "world" {
		t.Errorf("內容錯誤: %v", out)
	}
}

func BenchmarkWriteJSON(b *testing.B) {
	payload := map[string]any{
		"upstreams": []map[string]any{{"id": "u1", "healthy": true, "last_latency_ms": 42}},
		"accounts":  []map[string]any{{"username": "warp-aaaa", "upstream": "u1"}},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		writeJSON(httptest.NewRecorder(), http.StatusOK, payload)
	}
}
