package winvpn

import (
	"net/netip"
	"strconv"
	"strings"
)

// RouteCandidate is one default route (0.0.0.0/0 or ::/0) of the PC.
type RouteCandidate struct {
	LUID        uint64
	NextHop     netip.Addr
	RouteMetric uint32
	IfMetric    uint32
	Up          bool
}

// PickDefaultRoute chooses the route Windows itself would use for the
// tunnel's own UDP packets: the lowest route + interface metric among
// connected interfaces other than our adapter. ok is false when there is no
// such route (offline).
func PickDefaultRoute(cands []RouteCandidate, ourLUID uint64) (best RouteCandidate, ok bool) {
	for _, c := range cands {
		if c.LUID == ourLUID || !c.Up {
			continue
		}
		if !ok || c.RouteMetric+c.IfMetric < best.RouteMetric+best.IfMetric {
			best, ok = c, true
		}
	}
	return best, ok
}

// HostRoute is a route the helper added outside its own adapter (the
// endpoint exception). It is remembered so a crashed helper's route can be
// removed on the next start.
type HostRoute struct {
	Dest    netip.Prefix
	NextHop netip.Addr
	LUID    uint64
}

// String encodes the route for the crash-recovery record.
func (h HostRoute) String() string {
	return h.Dest.String() + "|" + h.NextHop.String() + "|" + strconv.FormatUint(h.LUID, 10)
}

// ParseHostRoute decodes a crash-recovery record. Only single-host routes
// are accepted, so a tampered record can never remove a wider route.
func ParseHostRoute(s string) (HostRoute, bool) {
	parts := strings.Split(s, "|")
	if len(parts) != 3 {
		return HostRoute{}, false
	}
	d, err1 := netip.ParsePrefix(parts[0])
	nh, err2 := netip.ParseAddr(parts[1])
	l, err3 := strconv.ParseUint(parts[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || l == 0 {
		return HostRoute{}, false
	}
	if d.Bits() != d.Addr().BitLen() || d.Addr().Is4() != nh.Is4() {
		return HostRoute{}, false
	}
	return HostRoute{Dest: d, NextHop: nh, LUID: l}, true
}
