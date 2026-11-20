//go:build windows

package winvpn

// What the adapter session needs from the platform-neutral VPN core
// (package vpn): something that carries the adapter's packets to the house
// and can report transfer counters. startCore is provided by
// core_bridge_windows.go.

// coreStats are the counters shown in the app.
type coreStats struct {
	LastHandshake int64 // unix seconds, 0 = never
	RxBytes       int64
	TxBytes       int64
}

type coreSession interface {
	Stats() coreStats
	Close()
}
