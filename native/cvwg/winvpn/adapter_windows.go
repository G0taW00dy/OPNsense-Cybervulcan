//go:build windows

package winvpn

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// AdapterName is the network adapter users see in Windows' settings.
const AdapterName = "Cybervulcan"

// adapterGUID is fixed so a re-created adapter reuses Windows' per-adapter
// settings (no "Cybervulcan 2", no pile of stale interface profiles).
var adapterGUID = windows.GUID{
	Data1: 0x6f3c2b1a,
	Data2: 0x9d4e,
	Data3: 0x4c7b,
	Data4: [8]byte{0xa1, 0x5e, 0x2f, 0x8c, 0x37, 0x0d, 0xc4, 0x91},
}

// manager owns at most one adapter session (helper process only).
type manager struct {
	mu   sync.Mutex
	sess *session
	last Status // shown when no session runs (last error)
}

type session struct {
	plan Plan
	dev  tun.Device
	luid winipcfg.LUID
	core coreSession

	mu        sync.Mutex
	closed    bool
	hostRoute *HostRoute
	monitor   *winipcfg.RouteChangeCallback
	repin     *time.Timer
}

// Start replaces any running session with a new one for r.
func (m *manager) Start(r StartRequest) error {
	plan, err := BuildPlan(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess != nil {
		m.sess.close()
		m.sess = nil
	}
	m.last = Status{State: StateStarting, Mode: plan.Mode}
	s, err := startSession(plan, r)
	if err != nil {
		m.last = Status{State: StateError, Mode: plan.Mode, Error: FriendlyError(err)}
		return errors.New(m.last.Error)
	}
	m.sess = s
	m.last = Status{}
	return nil
}

// Stop removes the adapter, routes and DNS.
func (m *manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess != nil {
		m.sess.close()
		m.sess = nil
	}
	m.last = Status{State: StateOff}
}

func (m *manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sess == nil {
		if m.last.State == "" {
			return Status{State: StateOff}
		}
		return m.last
	}
	st := Status{State: StateOn, Mode: m.sess.plan.Mode}
	if m.sess.core != nil {
		cs := m.sess.core.Stats()
		st.LastHandshake, st.RxBytes, st.TxBytes = cs.LastHandshake, cs.RxBytes, cs.TxBytes
	}
	return st
}

func startSession(plan Plan, r StartRequest) (s *session, err error) {
	dev, err := tun.CreateTUNWithRequestedGUID(AdapterName, &adapterGUID, plan.MTU)
	if err != nil {
		return nil, fmt.Errorf("could not create the %s network adapter: %w", AdapterName, err)
	}
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		dev.Close()
		return nil, errors.New("unexpected adapter type")
	}
	s = &session{plan: plan, dev: dev, luid: winipcfg.LUID(nt.LUID())}
	defer func() {
		if err != nil {
			s.close()
		}
	}()

	// 1. Keep the tunnel's own UDP packets on the real network.
	if plan.EndpointRoute {
		if err = s.pinEndpoint(); err != nil {
			return nil, err
		}
		mon, merr := winipcfg.RegisterRouteChangeCallback(s.onRouteChange)
		if merr != nil {
			return nil, fmt.Errorf("route monitor: %w", merr)
		}
		s.mu.Lock()
		s.monitor = mon
		s.mu.Unlock()
	}
	// 2. Addresses, routes, metric, MTU, DNS on the adapter.
	if err = configureAdapter(s.luid, plan); err != nil {
		return nil, err
	}
	// 3. Carry the packets to the house.
	if s.core, err = startCore(dev, plan, r); err != nil {
		return nil, err
	}
	return s, nil
}

func configureAdapter(luid winipcfg.LUID, plan Plan) error {
	if err := luid.SetIPAddresses(plan.Addresses); err != nil {
		return fmt.Errorf("set adapter address: %w", err)
	}
	routes := make([]*winipcfg.RouteData, 0, len(plan.Routes))
	for _, p := range plan.Routes {
		nh := netip.IPv4Unspecified()
		if p.Addr().Is6() {
			nh = netip.IPv6Unspecified()
		}
		routes = append(routes, &winipcfg.RouteData{Destination: p, NextHop: nh, Metric: 0})
	}
	if err := luid.SetRoutes(routes); err != nil {
		return fmt.Errorf("set routes: %w", err)
	}
	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		iface, err := luid.IPInterface(fam)
		if err != nil {
			if fam == windows.AF_INET6 {
				continue // IPv6 disabled on this PC: nothing can leak
			}
			return fmt.Errorf("adapter settings: %w", err)
		}
		if fam == windows.AF_INET {
			iface.NLMTU = uint32(plan.MTU)
		} else if plan.MTU >= 1280 {
			iface.NLMTU = uint32(plan.MTU)
		}
		// Set both ways: a fixed GUID means Windows remembers the last
		// session's settings for this adapter.
		iface.UseAutomaticMetric = !plan.LowMetric
		if plan.LowMetric {
			iface.Metric = 0
		}
		iface.DadTransmits = 0
		iface.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		if err := iface.Set(); err != nil && fam == windows.AF_INET {
			return fmt.Errorf("adapter settings: %w", err)
		}
	}
	// Always written (empty = none), so DNS left over from an earlier
	// "everything" session never applies in "home" mode.
	if err := luid.SetDNS(windows.AF_INET, plan.DNS, nil); err != nil {
		return fmt.Errorf("set DNS: %w", err)
	}
	_ = luid.SetDNS(windows.AF_INET6, nil, nil)
	return nil
}

// defaultRoute finds the PC's current default route for the endpoint's
// address family, ignoring our adapter.
func (s *session) defaultRoute() (RouteCandidate, error) {
	fam := winipcfg.AddressFamily(windows.AF_INET)
	if s.plan.Endpoint.Addr().Is6() {
		fam = windows.AF_INET6
	}
	rows, err := winipcfg.GetIPForwardTable2(fam)
	if err != nil {
		return RouteCandidate{}, err
	}
	var cands []RouteCandidate
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == s.luid {
			continue
		}
		c := RouteCandidate{LUID: uint64(r.InterfaceLUID), NextHop: r.NextHop.Addr(), RouteMetric: r.Metric}
		if ipif, err := r.InterfaceLUID.IPInterface(fam); err == nil {
			c.IfMetric = ipif.Metric
			c.Up = ipif.Connected
		}
		if ifrow, err := r.InterfaceLUID.Interface(); err == nil && ifrow.OperStatus != winipcfg.IfOperStatusUp {
			c.Up = false
		}
		cands = append(cands, c)
	}
	best, ok := PickDefaultRoute(cands, uint64(s.luid))
	if !ok {
		return RouteCandidate{}, errors.New("this PC has no internet connection (no default route)")
	}
	return best, nil
}

// pinEndpoint (re)creates the endpoint's host route via the current default
// gateway. Called at start and when the PC's network changes.
func (s *session) pinEndpoint() error {
	best, err := s.defaultRoute()
	if err != nil {
		return err
	}
	want := HostRoute{Dest: s.plan.EndpointHostRoute(), NextHop: best.NextHop, LUID: best.LUID}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || (s.hostRoute != nil && *s.hostRoute == want) {
		return nil
	}
	if err := winipcfg.LUID(want.LUID).AddRoute(want.Dest, want.NextHop, 0); err != nil &&
		!errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		return fmt.Errorf("route to the WireGuard endpoint: %w", err)
	}
	if old := s.hostRoute; old != nil {
		_ = winipcfg.LUID(old.LUID).DeleteRoute(old.Dest, old.NextHop)
	}
	s.hostRoute = &want
	saveHostRoutes([]HostRoute{want})
	return nil
}

func (s *session) onRouteChange(_ winipcfg.MibNotificationType, r *winipcfg.MibIPforwardRow2) {
	if r == nil || r.DestinationPrefix.PrefixLength != 0 || r.InterfaceLUID == s.luid {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	// Debounce: Wi-Fi switches produce bursts of route changes.
	if s.repin != nil {
		s.repin.Stop()
	}
	s.repin = time.AfterFunc(2*time.Second, func() { _ = s.pinEndpoint() })
}

func (s *session) close() {
	s.mu.Lock()
	s.closed = true
	mon := s.monitor
	s.monitor = nil
	s.mu.Unlock()
	if mon != nil {
		_ = mon.Unregister()
	}
	s.mu.Lock()
	if s.repin != nil {
		s.repin.Stop()
		s.repin = nil
	}
	hr := s.hostRoute
	s.hostRoute = nil
	s.mu.Unlock()

	if s.core != nil {
		s.core.Close()
		s.core = nil
	}
	// Closing a Wintun adapter that this process created deletes it, and
	// with it its addresses, routes and DNS servers.
	if s.dev != nil {
		_ = s.dev.Close()
		s.dev = nil
	}
	if hr != nil {
		_ = winipcfg.LUID(hr.LUID).DeleteRoute(hr.Dest, hr.NextHop)
	}
	saveHostRoutes(nil)
}
