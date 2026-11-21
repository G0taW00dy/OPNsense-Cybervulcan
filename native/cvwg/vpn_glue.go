package main

// Platform-neutral glue between the C exports (exports_vpn_<os>.go) and
// package vpn: one system-VPN session per process, fed by a tun.Device the
// platform created, dialling out through the current remote-access
// transport.
//
// Transports are looked up by name in vpnDialers. "wireguard" (default)
// dials through the tunnel started by cvwg_up, whichever one is current at
// dial time, so the tunnel can be restarted (new endpoint, keys) under a
// running VPN without touching it. Other transports (the built-in
// Tailscale engine) register themselves from their own file:
//
//	func init() { vpnDialers["tailscale"] = func() (vpn.Dialer, error) { ... } }

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/vpn"
	"golang.zx2c4.com/wireguard/tun"
)

// vpnStartConfig is the JSON given to cvvpn_start: vpn.Config plus the
// transport and a free-text mode label echoed back by the status.
type vpnStartConfig struct {
	vpn.Config
	Transport string `json:"transport,omitempty"` // "wireguard" (default)
	Mode      string `json:"mode,omitempty"`      // "home" | "everything" (label only)
}

// vpnStatus is what cvvpn_status returns.
type vpnStatus struct {
	Up        bool   `json:"up"`
	Mode      string `json:"mode,omitempty"`
	Transport string `json:"transport,omitempty"`
	// TransportUp: the remote-access transport is connected right now
	// (for WireGuard: a tunnel exists; it says nothing about a handshake).
	TransportUp bool `json:"transportUp"`
	vpn.Stats
	Error string `json:"error,omitempty"`
}

var (
	vpnMu        sync.Mutex
	vpnSession   *vpn.Session
	vpnMode      string
	vpnTransport string
	// vpnLastError survives the session, so the app can tell why it ended.
	vpnLastError string
)

var errNoTunnel = errors.New("remote access is not connected")

// wireguardDialer dials through the tunnel that is current at dial time.
var wireguardDialer = vpn.DialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
	mu.Lock()
	t := current
	mu.Unlock()
	if t == nil {
		return nil, errNoTunnel
	}
	return t.DialContext(ctx, network, address)
})

// vpnDialers maps a transport name to its dialer factory.
var vpnDialers = map[string]func() (vpn.Dialer, error){
	"wireguard": func() (vpn.Dialer, error) { return wireguardDialer, nil },
}

// transportUp reports whether the named transport can dial right now.
// Transports other than WireGuard register a check in vpnTransportUp.
var vpnTransportUp = map[string]func() bool{
	"wireguard": func() bool {
		mu.Lock()
		defer mu.Unlock()
		return current != nil
	},
}

// vpnStart starts (or replaces) the VPN session on dev. dev is closed on
// failure. Returns the JSON reply: {"up":true} or {"error":"..."}.
func vpnStart(dev tun.Device, cfgJSON string) string {
	fail := func(err error) string {
		if dev != nil {
			_ = dev.Close()
		}
		vpnMu.Lock()
		vpnLastError = err.Error()
		vpnMu.Unlock()
		return jsonString(map[string]string{"error": err.Error()})
	}
	var cfg vpnStartConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return fail(fmt.Errorf("bad VPN config: %v", err))
	}
	opts, err := cfg.Config.Options()
	if err != nil {
		return fail(err)
	}
	name := strings.ToLower(strings.TrimSpace(cfg.Transport))
	if name == "" {
		name = "wireguard"
	}
	factory, ok := vpnDialers[name]
	if !ok {
		return fail(fmt.Errorf("remote access engine %q is not available in this build", name))
	}
	d, err := factory()
	if err != nil {
		return fail(err)
	}

	vpnMu.Lock()
	defer vpnMu.Unlock()
	if vpnSession != nil {
		_ = vpnSession.Close()
		vpnSession = nil
	}
	s, err := vpn.Start(dev, opts, d)
	if err != nil {
		_ = dev.Close()
		vpnLastError = err.Error()
		return jsonString(map[string]string{"error": err.Error()})
	}
	vpnSession, vpnMode, vpnTransport, vpnLastError = s, cfg.Mode, name, ""
	return jsonString(map[string]bool{"up": true})
}

// vpnStatusJSON reports the session (and why the last one ended).
func vpnStatusJSON() string {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	st := vpnStatus{Mode: vpnMode, Transport: vpnTransport, Error: vpnLastError}
	if f, ok := vpnTransportUp[vpnTransport]; ok {
		st.TransportUp = f()
	}
	if vpnSession == nil {
		return jsonString(st)
	}
	select {
	case <-vpnSession.Done():
		// The interface went away (VPN revoked, fd closed): clean up.
		stats := vpnSession.Stats()
		_ = vpnSession.Close()
		vpnSession = nil
		if stats.LastError != "" {
			vpnLastError = stats.LastError
		}
		st.Error = vpnLastError
		return jsonString(st)
	default:
	}
	st.Up = true
	st.Stats = vpnSession.Stats()
	return jsonString(st)
}

// vpnStop ends the session and closes its device.
func vpnStop() {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	if vpnSession != nil {
		_ = vpnSession.Close()
		vpnSession = nil
	}
	vpnMode, vpnTransport = "", ""
}

func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"internal: json"}`
	}
	return string(b)
}
