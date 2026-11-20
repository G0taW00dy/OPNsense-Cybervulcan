//go:build android

package ts

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"tailscale.com/net/netmon"
)

// Android does not let apps enumerate network interfaces (netlink is
// blocked for apps since Android 11), so net.Interfaces fails inside the
// app. The Tailscale Android app answers this from Java; tsnet in a plain
// c-shared library has nothing, and netmon would fail to start. Register a
// getter that uses net.Interfaces when it works and otherwise reports one
// synthetic interface carrying the addresses the kernel picks for outbound
// traffic (found by "connecting" UDP sockets to a public resolver address,
// which sends nothing; real addresses because Android may route
// documentation ranges specially).
func init() {
	netmon.RegisterInterfaceGetter(androidInterfaces)
}

func androidInterfaces() ([]netmon.Interface, error) {
	if ifs, err := net.Interfaces(); err == nil && len(ifs) > 0 {
		out := make([]netmon.Interface, len(ifs))
		for i := range ifs {
			out[i].Interface = &ifs[i]
		}
		return out, nil
	}
	var addrs []net.Addr
	if ip, ok := outboundIP("udp4", "1.1.1.1:53"); ok {
		addrs = append(addrs, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(32, 32)})
	}
	if ip, ok := outboundIP("udp6", "[2606:4700:4700::1111]:53"); ok {
		addrs = append(addrs, &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(128, 128)})
	}
	if len(addrs) == 0 {
		return nil, errors.New("no network")
	}
	return []netmon.Interface{{
		Interface: &net.Interface{Index: 1, MTU: 1500, Name: "android", Flags: net.FlagUp | net.FlagRunning},
		AltAddrs:  addrs,
	}}, nil
}

// outboundIP is the local address the kernel would use to reach addr.
// Dialing UDP only selects a route; no packet is sent.
func outboundIP(network, addr string) (netip.Addr, bool) {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial(network, addr)
	if err != nil {
		return netip.Addr{}, false
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() {
		return netip.Addr{}, false
	}
	return ip, true
}
