//go:build windows

package winvpn

// TEMPORARY STUB - swapped for the real bridge once package vpn (branch
// agent/android-vpn) is merged: build the WireGuard dialer from r and call
// vpn.Start(dev, opts, dialer). Until then the adapter is created and
// configured, then rolled back with this error.

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

func startCore(dev tun.Device, plan Plan, r StartRequest) (coreSession, error) {
	_, _, _ = dev, plan, r
	return nil, errors.New("the home link is not available in this build yet")
}
