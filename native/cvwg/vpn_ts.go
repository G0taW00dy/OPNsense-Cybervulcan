package main

// Built-in Tailscale as a transport for the system-VPN modes ("home devices",
// "everything"): the VPN session dials every flow through the tsnet engine
// started by cvts_start. "Everything" additionally needs the router to be an
// approved exit node (docs/ROUTER-REMOTE-MODES.md); without it only tailnet
// and advertised subnet addresses are reachable, so the device has no
// internet while connected - the safe failure.

import (
	"context"
	"net"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/vpn"
)

var tailscaleDialer = vpn.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
	e := tsService.Engine()
	if e == nil {
		return nil, errNoTunnel
	}
	return e.DialContext(ctx, network, address)
})

func init() {
	vpnDialers["tailscale"] = func() (vpn.Dialer, error) { return tailscaleDialer, nil }
	vpnTransportUp["tailscale"] = func() bool {
		e := tsService.Engine()
		return e != nil && e.Ready()
	}
}
