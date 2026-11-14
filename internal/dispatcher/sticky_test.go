package dispatcher

// 覆蓋 agent/question.md 第 16 節 A51–A53：
//   A51 每帳號黏性出口參與選路（sticky[username] 健康時恆為首位）
//   A52 延遲型換黏容差（margin 0 = 僅不通才飄移；需雙方延遲已知且超出容差）
//   A53 飄移目標排除延遲未知者；prefer 切換清黏住表、margin 單獨變動保留

import (
	"context"
	"testing"
	"time"

	"multi-cf-proxy/internal/tunnel"
)

// route 撥一次並回傳實際出口。
func route(t *testing.T, svc *Service, user, pw string) string {
	t.Helper()
	conn, used, err := svc.Route(context.Background(), user, pw, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Route(%s) 失敗: %v", user, err)
	}
	conn.Close()
	return used
}

// TestStickyIsPerAccount A51：兩帳號各自黏一個出口，互不影響。
func TestStickyIsPerAccount(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 0)

	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
		t.Fatalf("aaaa 初始應黏最快 u2, got %s", got)
	}

	// u2 不通 → bbbb 只能黏 u1
	reg.health["u2"] = false
	reg.healthy = []tunnel.Tunnel{reg.bound["u1"]}
	reg.sorted = []tunnel.Tunnel{reg.bound["u1"]}
	if got := route(t, svc, "warp-bbbb", "pw2"); got != "u1" {
		t.Fatalf("bbbb 應黏 u1, got %s", got)
	}

	// u2 恢復且最快：aaaa 黏住的 u2 回來 → 回 u2；bbbb 黏 u1 不動
	reg.health["u2"] = true
	reg.healthy = []tunnel.Tunnel{reg.bound["u2"], reg.bound["u1"]}
	reg.sorted = []tunnel.Tunnel{reg.bound["u2"], reg.bound["u1"]}
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
		t.Errorf("aaaa 應黏回 u2, got %s", got)
	}
	if got := route(t, svc, "warp-bbbb", "pw2"); got != "u1" {
		t.Errorf("bbbb 應維持黏 u1（不因 u2 更快而飄）, got %s", got)
	}
}

// TestMarginGate A52：容差三態（未達/等於/超過）。
func TestMarginGate(t *testing.T) {
	cases := []struct {
		name   string
		margin int
		u1Lat  time.Duration
		want   string
	}{
		{"容差零永不換黏", 0, 1 * time.Millisecond, "u2"},
		{"差距未達容差", 20, 35 * time.Millisecond, "u2"},
		{"差距等於容差", 20, 30 * time.Millisecond, "u2"},
		{"差距超過容差", 20, 29 * time.Millisecond, "u1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, reg := newLatService(t)
			svc.SetLatencyRouting(true, c.margin)
			if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
				t.Fatalf("前置：應黏 u2, got %s", got)
			}
			reg.lat["u1"] = c.u1Lat
			reg.sorted = []tunnel.Tunnel{reg.bound["u1"], reg.bound["u2"]}
			if got := route(t, svc, "warp-aaaa", "pw1"); got != c.want {
				t.Errorf("出口 = %s, want %s", got, c.want)
			}
		})
	}
}

// TestMarginGateHoldsWhenLatencyUnknown A52：任一方延遲未知時不因容差換黏。
func TestMarginGateHoldsWhenLatencyUnknown(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 1)
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
		t.Fatalf("前置：應黏 u2, got %s", got)
	}

	reg.lat["u2"] = 0 // 黏住者重建後讀數歸零
	reg.sorted = []tunnel.Tunnel{reg.bound["u1"], reg.bound["u2"]}
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
		t.Errorf("黏住者延遲未知應維持黏住, got %s", got)
	}
}

// TestDriftSkipsUnknownLatency A53：黏住者不通時，飄移目標排除延遲未知者。
func TestDriftSkipsUnknownLatency(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 0)
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
		t.Fatalf("前置：應黏 u2, got %s", got)
	}

	u3 := &stubTunnel{id: "u3"}
	reg.bound["u3"] = u3
	reg.health["u3"] = true
	reg.health["u2"] = false
	reg.lat["u3"] = 0 // 剛重建：延遲未知
	reg.healthy = []tunnel.Tunnel{u3, reg.bound["u1"]}
	reg.sorted = []tunnel.Tunnel{u3, reg.bound["u1"]} // 未知殿後前仍可能排首位
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u1" {
		t.Errorf("應跳過延遲未知的 u3 選 u1, got %s", got)
	}
}

// TestDriftUsesUnknownWhenNoneKnown A53：健康集合全無讀數時才接受未知者。
func TestDriftUsesUnknownWhenNoneKnown(t *testing.T) {
	svc, reg := newLatService(t)
	svc.SetLatencyRouting(true, 0)
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
		t.Fatalf("前置：應黏 u2, got %s", got)
	}

	reg.health["u2"] = false
	reg.lat["u1"] = 0
	reg.healthy = []tunnel.Tunnel{reg.bound["u1"]}
	reg.sorted = []tunnel.Tunnel{reg.bound["u1"]}
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u1" {
		t.Errorf("全無讀數時應接受未知者 u1, got %s", got)
	}
}

// TestMarginChangeKeepsSticky A53：margin 單獨變動保留黏住表，prefer 切換才清空。
func TestMarginChangeKeepsSticky(t *testing.T) {
	svc, _ := newLatService(t)
	svc.SetLatencyRouting(true, 0)
	if got := route(t, svc, "warp-aaaa", "pw1"); got != "u2" {
		t.Fatalf("前置：應黏 u2, got %s", got)
	}

	svc.SetLatencyRouting(true, 50)
	if snap := svc.EgressSnapshot(); snap["warp-aaaa"] != "u2" {
		t.Errorf("僅改容差應保留黏住表, got %v", snap)
	}

	svc.SetLatencyRouting(false, 50)
	if snap := svc.EgressSnapshot(); len(snap) != 0 {
		t.Errorf("關閉全域模式應清空黏住表, got %v", snap)
	}
}
