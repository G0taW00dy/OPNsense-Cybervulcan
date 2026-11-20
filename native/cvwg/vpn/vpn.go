// Package vpn turns a system VPN interface (a tun.Device: Android
// VpnService fd, Windows Wintun adapter) into ordinary TCP and UDP
// connections made through a pluggable Dialer.
//
// Packets the operating system routes into the interface are fed into a
// gVisor netstack that terminates every TCP and UDP flow locally and opens
// the matching connection with the Dialer (WireGuard to the home router,
// built-in Tailscale, ...):
//
//	app --IP packets--> tun.Device --netstack--> Dialer.DialContext("tcp"|"udp", "dst:port")
//
// TCP is connect-on-SYN: the handshake with the app only completes once the
// Dialer has connected, so a destination the far side cannot reach is
// refused (RST) instead of accepted and then dropped. Destinations outside
// Options.Allowed are refused (TCP RST) or dropped (UDP, everything else).
// ICMP is dropped: a ping through a TCP/UDP dialer cannot be answered
// truthfully, and the netstack must not pretend every address is up.
//
// The package is platform neutral and has no cgo: the platform glue creates
// the tun.Device and the Dialer and calls Start.
package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Dialer opens connections on the far side of the VPN. network is "tcp" or
// "udp"; address is always a literal "ip:port" (IPv6 as "[ip]:port").
// *net.Dialer, golang.zx2c4.com/wireguard/tun/netstack.Net and the tunnel
// and Tailscale packages of this library all satisfy it.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialerFunc adapts a function to the Dialer interface.
type DialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialContext calls f.
func (f DialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// Options tune a Session. The zero value works: MTU 1280, every destination
// allowed, no DNS redirect, default timeouts.
type Options struct {
	// MTU of the interface (must match what the OS was told). Default 1280.
	MTU int

	// DNS, when valid, receives every DNS query (UDP and TCP port 53, to any
	// address): the VPN's DNS server and any resolver an app hard-codes are
	// all answered by this server, so lookups cannot leak around it.
	DNS netip.AddrPort

	// Allowed destination prefixes. Empty = everything. Others are refused.
	Allowed []netip.Prefix

	// DialTimeout bounds each Dialer call. Default 10 s.
	DialTimeout time.Duration

	// TCPIdleTimeout closes a TCP flow with no traffic in either direction
	// for this long. Default 2 h (TCP keepalives keep healthy flows open).
	TCPIdleTimeout time.Duration

	// UDPIdleTimeout ends a UDP flow (and its upstream socket) after this
	// long without packets. Default 60 s (DNS flows: 10 s).
	UDPIdleTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.MTU <= 0 {
		o.MTU = 1280
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.TCPIdleTimeout <= 0 {
		o.TCPIdleTimeout = 2 * time.Hour
	}
	if o.UDPIdleTimeout <= 0 {
		o.UDPIdleTimeout = 60 * time.Second
	}
	return o
}

// Config is the JSON form of Options used by the C exports
// (cvvpn_start) and the apps.
//
//	{"mtu":1280,"dns":"10.10.10.254","allowed":["10.10.10.0/24","10.10.10.254/32"]}
type Config struct {
	MTU int `json:"mtu,omitempty"`
	// DNS server ("ip" or "ip:port", port 53 by default). Empty = no redirect.
	DNS string `json:"dns,omitempty"`
	// Allowed destination prefixes or plain IPs. Empty = everything.
	Allowed []string `json:"allowed,omitempty"`
	// Timeouts in seconds (0 = default).
	DialTimeoutSec    int `json:"dialTimeoutSec,omitempty"`
	TCPIdleTimeoutSec int `json:"tcpIdleSec,omitempty"`
	UDPIdleTimeoutSec int `json:"udpIdleSec,omitempty"`
}

// Options validates c.
func (c Config) Options() (Options, error) {
	o := Options{
		MTU:            c.MTU,
		DialTimeout:    time.Duration(c.DialTimeoutSec) * time.Second,
		TCPIdleTimeout: time.Duration(c.TCPIdleTimeoutSec) * time.Second,
		UDPIdleTimeout: time.Duration(c.UDPIdleTimeoutSec) * time.Second,
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 65535) {
		return o, fmt.Errorf("MTU %d is out of range (576-65535)", c.MTU)
	}
	if d := strings.TrimSpace(c.DNS); d != "" {
		if ap, err := netip.ParseAddrPort(d); err == nil {
			o.DNS = ap
		} else if a, err := netip.ParseAddr(d); err == nil {
			o.DNS = netip.AddrPortFrom(a, 53)
		} else {
			return o, fmt.Errorf("DNS server %q is not an IP address", d)
		}
	}
	for _, s := range c.Allowed {
		p, err := ParsePrefix(s)
		if err != nil {
			return o, err
		}
		o.Allowed = append(o.Allowed, p)
	}
	return o, nil
}

// ParsePrefix accepts "a.b.c.d/nn", "a.b.c.d" (host route) and the IPv6
// equivalents, and returns the masked prefix.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
}

// Stats is a snapshot of a Session's counters.
type Stats struct {
	TCPActive  int64 `json:"tcpActive"`
	TCPTotal   int64 `json:"tcpTotal"`
	UDPActive  int64 `json:"udpActive"`
	UDPTotal   int64 `json:"udpTotal"`
	TxBytes    int64 `json:"tx"`         // app -> far side (payload bytes)
	RxBytes    int64 `json:"rx"`         // far side -> app
	Blocked    int64 `json:"blocked"`    // flows refused by Allowed
	DialErrors int64 `json:"dialErrors"` // flows the Dialer could not open
	// LastError is the latest dial error (no secrets: addresses only).
	LastError string `json:"lastError,omitempty"`
	// Started is the unix time the session started.
	Started int64 `json:"started"`
}

// ErrClosed is returned by Start on a device that closed during set-up.
var ErrClosed = errors.New("vpn: session closed")

type counters struct {
	tcpActive, tcpTotal, udpActive, udpTotal atomic.Int64
	tx, rx, blocked, dialErrors              atomic.Int64
}

// allowed reports whether dst may be reached.
func (o *Options) allowed(dst netip.Addr) bool {
	if len(o.Allowed) == 0 {
		return true
	}
	dst = dst.Unmap()
	for _, p := range o.Allowed {
		if p.Contains(dst) {
			return true
		}
	}
	return false
}

// target maps a flow's destination to where the Dialer must connect,
// applying the DNS redirect.
func (o *Options) target(dst netip.AddrPort) netip.AddrPort {
	if o.DNS.IsValid() && dst.Port() == 53 {
		return o.DNS
	}
	return dst
}

// countingConn wraps the upstream conn to count payload bytes and track the
// last activity for idle timeouts.
type idleTracker struct{ last atomic.Int64 }

func (t *idleTracker) touch() { t.last.Store(time.Now().UnixNano()) }
func (t *idleTracker) idleFor() time.Duration {
	return time.Duration(time.Now().UnixNano() - t.last.Load())
}

// relay copies both ways until either side is done or the flow is idle for
// idle. It returns when both copies have stopped.
func relay(app, far net.Conn, idle time.Duration, c *counters, halfClose bool) {
	var it idleTracker
	it.touch()
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = app.Close()
			_ = far.Close()
		})
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn, n *atomic.Int64) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			k, err := src.Read(buf)
			if k > 0 {
				it.touch()
				n.Add(int64(k))
				if _, werr := dst.Write(buf[:k]); werr != nil {
					closeBoth()
					return
				}
			}
			if err != nil {
				if halfClose && errors.Is(err, io.EOF) {
					if cw, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
						return
					}
				}
				closeBoth()
				return
			}
		}
	}
	wg.Add(2)
	go cp(far, app, &c.tx)
	go cp(app, far, &c.rx)
	go func() {
		wg.Wait()
		close(done)
	}()
	tick := idle / 4
	if tick > 30*time.Second {
		tick = 30 * time.Second
	}
	if tick < 10*time.Millisecond {
		tick = 10 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-done:
			closeBoth()
			return
		case <-t.C:
			if it.idleFor() >= idle {
				closeBoth()
			}
		}
	}
}
