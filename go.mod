module multi-cf-proxy

go 1.26.3

// 收編 wireguard-go netstack panic 根治（VPS 生產雙機已驗證）：
// 上游 tun/netstack netTun.WriteNotify 無鎖發 channel 與 Close 關閉 channel
// 存在競態（panic: send on closed channel，每 10-15 分鐘一次）；上游
// PR #85/#134/#149 均未合併。改用 pingmike2 fork 分支 fix/netstack-ctx
// （= 本倉庫原基線 ecfc5a8d5446 + cherry-pick PR #134 單筆 4b7ace59a09c，
// 刪 channel 改 ctx+ep.ReadContext，徹底移除 panic 通道）。
replace golang.zx2c4.com/wireguard => github.com/pingmike2/wireguard-go v0.0.0-20261023010644-a7d3f36bf23f

require (
	golang.org/x/crypto v0.55.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
