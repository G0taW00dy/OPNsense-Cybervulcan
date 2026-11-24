package winvpn

import (
	"net/netip"
	"testing"
)

func TestPickDefaultRoute(t *testing.T) {
	wifi := RouteCandidate{LUID: 1, NextHop: netip.MustParseAddr("192.168.1.1"), RouteMetric: 0, IfMetric: 35, Up: true}
	eth := RouteCandidate{LUID: 2, NextHop: netip.MustParseAddr("192.168.0.1"), RouteMetric: 0, IfMetric: 25, Up: true}
	ours := RouteCandidate{LUID: 9, NextHop: netip.IPv4Unspecified(), RouteMetric: 0, IfMetric: 0, Up: true}
	down := RouteCandidate{LUID: 3, NextHop: netip.MustParseAddr("10.0.0.1"), IfMetric: 1, Up: false}

	got, ok := PickDefaultRoute([]RouteCandidate{wifi, ours, eth, down}, 9)
	if !ok || got.LUID != 2 {
		t.Errorf("got %+v %v, want ethernet", got, ok)
	}
	if _, ok := PickDefaultRoute([]RouteCandidate{ours, down}, 9); ok {
		t.Error("offline PC: no default route expected")
	}
}

func TestHostRouteRecord(t *testing.T) {
	h := HostRoute{Dest: netip.MustParsePrefix("203.0.113.7/32"), NextHop: netip.MustParseAddr("192.168.1.1"), LUID: 1234}
	got, ok := ParseHostRoute(h.String())
	if !ok || got != h {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
	for _, bad := range []string{
		"", "0.0.0.0/0|192.168.1.1|5", "10.0.0.0/8|192.168.1.1|5",
		"203.0.113.7/32|fe80::1|5", "203.0.113.7/32|192.168.1.1|0", "203.0.113.7/32|192.168.1.1",
		"203.0.113.7/32|192.168.1.1|x",
	} {
		if _, ok := ParseHostRoute(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
