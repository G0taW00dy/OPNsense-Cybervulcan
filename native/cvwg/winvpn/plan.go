// Package winvpn is the Windows side of the remote access modes "home" and
// "everything": a Wintun adapter named "Cybervulcan" whose packets are carried
// to the house by the platform-neutral VPN core.
//
// Creating the adapter and changing routes / DNS needs admin rights, while
// the tray app runs as the normal user. The work is therefore done by a small
// elevated helper (the app's own exe started with --vpn-helper through the
// UAC prompt) that talks to the tray app over a named pipe which only the
// signed-in user can open. The pipe protocol accepts exactly three requests
// (start / stop / status) with validated parameters; see protocol.go.
//
// This file and protocol.go are plain Go (no Windows APIs) so the route and
// DNS plan and the protocol validation are unit-tested on any OS.
package winvpn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Modes that need the adapter. "app" (the default) never reaches this code:
// it is the user-space tunnel of package tunnel, without admin rights.
const (
	ModeHome       = "home"
	ModeEverything = "everything"
)

// Limits for validated input.
const (
	maxHomeCIDRs  = 64
	minHomeBits   = 8 // wider than a /8 is not "home devices": use everything
	defaultMTU    = 1280
	minMTU        = 576
	maxMTU        = 1500
	maxKeepalive  = 65535
	maxFieldBytes = 128
)

// blockV6Addr is a unique-local address given to the adapter in
// "everything" mode so the IPv6 catch-all routes below have a source
// address. The core only carries IPv4 to the house, so IPv6 sent into the
// adapter is dropped: apps fall back to IPv4 instead of leaking IPv6
// around the tunnel.
var blockV6Addr = netip.MustParsePrefix("fd63:7676:7076::2/128")

// StartRequest is what the tray app asks the helper for. Every field is
// validated by Validate (and again by BuildPlan) before anything changes on
// the PC. Keys are WireGuard keys (base64); never logged.
type StartRequest struct {
	Mode string `json:"mode"`

	PrivateKey    string `json:"privateKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	PresharedKey  string `json:"presharedKey,omitempty"`

	// Endpoint of the router's WireGuard port, already resolved: "ip:port".
	Endpoint string `json:"endpoint"`

	// Address is this PC's tunnel address, e.g. "10.10.99.2/32".
	Address string `json:"address"`

	// RouterIP is the router's LAN IPv4 (always routed into the adapter;
	// it is the DNS server in "everything" mode).
	RouterIP string `json:"routerIp"`

	// HomeCIDRs are the home devices for "home" mode (e.g. the NAS).
	HomeCIDRs []string `json:"homeCidrs,omitempty"`

	Keepalive int `json:"keepalive"`
	MTU       int `json:"mtu,omitempty"`
}

// String is safe for logs: no keys.
func (r StartRequest) String() string {
	return fmt.Sprintf("StartRequest(%s, %s via %s)", r.Mode, r.Address, r.Endpoint)
}

// Plan is everything the helper changes on the PC for one session.
type Plan struct {
	Mode string

	// Addresses given to the adapter.
	Addresses []netip.Prefix

	// Routes sent into the adapter (on-link, metric 0).
	Routes []netip.Prefix

	// AllowedIPs the WireGuard peer may carry (IPv4 only).
	AllowedIPs []netip.Prefix

	// DNS servers for the adapter; empty = DNS is not changed.
	DNS []netip.Addr

	// Endpoint is the WireGuard server. When EndpointRoute is true it lies
	// inside Routes, so a host route via the PC's original default gateway
	// keeps the tunnel's own UDP packets out of the adapter.
	Endpoint      netip.AddrPort
	EndpointRoute bool

	// LowMetric makes the adapter the preferred interface (everything mode:
	// its DNS server is asked first).
	LowMetric bool

	MTU int
}

func checkKey(name, b64 string, optional bool) error {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		if optional {
			return nil
		}
		return fmt.Errorf("%s is missing", name)
	}
	if len(b64) > maxFieldBytes {
		return fmt.Errorf("%s is not a WireGuard key", name)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("%s is not a WireGuard key", name)
	}
	return nil
}

// parseHostPrefix accepts "a.b.c.d" (as /32) or "a.b.c.d/n" (IPv4 only),
// returning the masked prefix.
func parseHostPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxFieldBytes {
		return netip.Prefix{}, errors.New("too long")
	}
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, err
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, errors.New("only IPv4 is carried to the house")
	}
	return p.Masked(), nil
}

// usableUnicast rejects addresses that must never be sent into the tunnel.
func usableUnicast(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// Validate checks the request without building the plan.
func (r *StartRequest) Validate() error {
	_, err := BuildPlan(*r)
	return err
}

// BuildPlan validates r and works out addresses, routes and DNS. Errors are
// plain English (shown to the user).
func BuildPlan(r StartRequest) (Plan, error) {
	var p Plan
	switch strings.TrimSpace(r.Mode) {
	case ModeHome, ModeEverything:
		p.Mode = strings.TrimSpace(r.Mode)
	default:
		return p, fmt.Errorf("unknown mode %q (home or everything)", r.Mode)
	}
	if err := checkKey("this PC's private key", r.PrivateKey, false); err != nil {
		return p, err
	}
	if err := checkKey("router public key", r.PeerPublicKey, false); err != nil {
		return p, err
	}
	if err := checkKey("pre-shared key", r.PresharedKey, true); err != nil {
		return p, err
	}
	if len(r.Endpoint) > maxFieldBytes {
		return p, errors.New("endpoint is too long")
	}
	ep, err := netip.ParseAddrPort(strings.TrimSpace(r.Endpoint))
	if err != nil || ep.Port() == 0 || !usableUnicast(ep.Addr().Unmap()) {
		return p, fmt.Errorf("endpoint %q must be ip:port", r.Endpoint)
	}
	p.Endpoint = netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())

	local, err := parseHostPrefix(r.Address)
	if err != nil || !usableUnicast(local.Addr()) {
		return p, fmt.Errorf("tunnel address %q is not valid (e.g. 10.10.99.2/32)", r.Address)
	}
	// The adapter carries just this host address; the routes decide the rest.
	p.Addresses = []netip.Prefix{netip.PrefixFrom(local.Addr(), 32)}

	router, err := parseHostPrefix(r.RouterIP)
	if err != nil || router.Bits() != 32 || !usableUnicast(router.Addr()) {
		return p, fmt.Errorf("router LAN IP %q is not a valid IPv4 address", r.RouterIP)
	}
	if r.Keepalive < 0 || r.Keepalive > maxKeepalive {
		return p, errors.New("keepalive must be 0-65535 seconds")
	}
	p.MTU = r.MTU
	if p.MTU == 0 {
		p.MTU = defaultMTU
	}
	if p.MTU < minMTU || p.MTU > maxMTU {
		return p, fmt.Errorf("MTU must be %d-%d", minMTU, maxMTU)
	}

	switch p.Mode {
	case ModeHome:
		if len(r.HomeCIDRs) > maxHomeCIDRs {
			return p, fmt.Errorf("at most %d home devices", maxHomeCIDRs)
		}
		routes := []netip.Prefix{router}
		for _, s := range r.HomeCIDRs {
			h, err := parseHostPrefix(s)
			if err != nil || (h.Bits() == 32 && !usableUnicast(h.Addr())) {
				return p, fmt.Errorf("home device %q is not an IPv4 address or range", s)
			}
			if h.Bits() < minHomeBits {
				return p, fmt.Errorf("home device range %s is too wide - use \"Everything\" instead", h)
			}
			if h.Addr().IsLoopback() || h.Addr().IsMulticast() || h.Addr().IsLinkLocalUnicast() {
				return p, fmt.Errorf("home device %s cannot be reached through the house", h)
			}
			routes = appendUnique(routes, h)
		}
		p.Routes = routes
		p.AllowedIPs = routes
	case ModeEverything:
		// Two halves instead of 0.0.0.0/0: more specific than the PC's own
		// default route, which stays in place for a clean fallback.
		p.Routes = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/1"),
			netip.MustParsePrefix("128.0.0.0/1"),
			// IPv6 catch-all into the adapter (dropped there): no IPv6 leak.
			netip.MustParsePrefix("::/1"),
			netip.MustParsePrefix("8000::/1"),
		}
		p.Addresses = append(p.Addresses, blockV6Addr)
		p.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		p.DNS = []netip.Addr{router.Addr()}
		p.LowMetric = true
	}
	for _, rt := range p.Routes {
		if rt.Contains(p.Endpoint.Addr()) {
			p.EndpointRoute = true
			break
		}
	}
	return p, nil
}

func appendUnique(list []netip.Prefix, p netip.Prefix) []netip.Prefix {
	for _, q := range list {
		if q == p {
			return list
		}
	}
	return append(list, p)
}

// EndpointHostRoute is the host route (/32 or /128) for the endpoint.
func (p Plan) EndpointHostRoute() netip.Prefix {
	a := p.Endpoint.Addr()
	return netip.PrefixFrom(a, a.BitLen())
}
