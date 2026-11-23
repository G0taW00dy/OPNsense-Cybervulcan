//go:build windows

package winvpn

import (
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Crash recovery. The adapter itself needs none: Wintun removes an adapter
// when the process that created it ends, crash or not, and its addresses,
// routes and DNS go with it. The one change outside the adapter - the host
// route to the WireGuard endpoint on the real network adapter - is recorded
// here (HKLM, writable by administrators only) and removed by the next
// helper start.
const (
	stateKey   = `SOFTWARE\Cybervulcan\VpnHelper`
	stateValue = "HostRoutes"
)

func saveHostRoutes(routes []HostRoute) {
	if len(routes) == 0 {
		// Nothing outstanding: leave no trace in the registry.
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, stateKey)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\Cybervulcan`) // only if empty
		return
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, stateKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	list := make([]string, len(routes))
	for i, r := range routes {
		list[i] = r.String()
	}
	_ = k.SetStringsValue(stateValue, list)
}

// cleanupStale removes host routes (and, v2.2.1, the DNS lock rule) left
// behind by a helper that crashed.
func cleanupStale() {
	clearDNSLock()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, stateKey, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	list, _, err := k.GetStringsValue(stateValue)
	k.Close()
	if err != nil {
		return
	}
	for _, s := range list {
		if r, ok := ParseHostRoute(s); ok {
			_ = winipcfg.LUID(r.LUID).DeleteRoute(r.Dest, r.NextHop)
		}
	}
	saveHostRoutes(nil)
}
