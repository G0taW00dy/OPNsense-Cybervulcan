//go:build windows

package winvpn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

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
	last Status // shown when no session runs (last error / off)

	// listenPackets opens the packet pipe for a new session and returns a
	// function that waits for the verified tray app (helper_windows.go).
	listenPackets func() (accept func() (net.Conn, error), stop func(), err error)
}

type session struct {
	plan Plan
	dev  tun.Device
	luid winipcfg.LUID

	attached atomic.Bool // packet pipe connected
	dead     atomic.Bool // packet pump ended
	pumpErr  atomic.Value

	mu         sync.Mutex
	closed     bool
	pkt        net.Conn
	stopListen func()
	hostRoutes map[netip.Addr]HostRoute
	monitor    *winipcfg.RouteChangeCallback
	repin      *time.Timer
}

// Start replaces any running session with a new one for r: adapter,
// addresses, routes, DNS, bypass host routes, then (in the background) the
// packet pipe to the tray app.
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
	s, err := startSession(plan)
	if err != nil {
		m.last = Status{State: StateError, Mode: plan.Mode, Error: FriendlyError(err)}
		return errors.New(m.last.Error)
	}
	accept, stop, err := m.listenPackets()
	if err != nil {
		s.close()
		m.last = Status{State: StateError, Mode: plan.Mode, Error: "could not open the packet pipe"}
		return errors.New(m.last.Error)
	}
	s.stopListen = stop
	m.sess = s
	go s.attach(accept)
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
	s := m.sess
	if s == nil {
		if m.last.State == "" {
			return Status{State: StateOff}
		}
		return m.last
	}
	if s.dead.Load() {
		msg, _ := s.pumpErr.Load().(string)
		if msg == "" {
			msg = "The home link stopped."
		}
		s.close()
		m.sess = nil
		m.last = Status{State: StateError, Mode: s.plan.Mode, Error: msg}
		return m.last
	}
	if !s.attached.Load() {
		return Status{State: StateStarting, Mode: s.plan.Mode}
	}
	return Status{State: StateOn, Mode: s.plan.Mode}
}

func startSession(plan Plan) (s *session, err error) {
	dev, err := tun.CreateTUNWithRequestedGUID(AdapterName, &adapterGUID, plan.MTU)
	if err != nil {
		return nil, fmt.Errorf("could not create the %s network adapter: %w", AdapterName, err)
	}
	nt, ok := dev.(*tun.NativeTun)
	if !ok {
		dev.Close()
		return nil, errors.New("unexpected adapter type")
	}
	s = &session{plan: plan, dev: dev, luid: winipcfg.LUID(nt.LUID()), hostRoutes: map[netip.Addr]HostRoute{}}
	defer func() {
		if err != nil {
			s.close()
		}
	}()

	// 1. Keep the tunnel's own UDP packets (and the router) on the real
	//    network.
	if len(plan.Bypass) > 0 {
		if err = s.pinBypass(); err != nil {
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
	return s, nil
}

// attach waits for the tray app on the packet pipe, then relays packets
// between the adapter and the pipe until either side ends.
func (s *session) attach(accept func() (net.Conn, error)) {
	conn, err := accept()
	s.mu.Lock()
	if s.stopListen != nil {
		s.stopListen()
		s.stopListen = nil
	}
	if err != nil || s.closed {
		s.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		s.pumpErr.Store("The app did not connect to the home link.")
		s.dead.Store(true)
		return
	}
	s.pkt = conn
	s.mu.Unlock()
	s.attached.Store(true)

	done := make(chan string, 2)
	go func() { done <- s.adapterToPipe(conn) }()
	go func() { done <- s.pipeToAdapter(conn) }()
	msg := <-done
	if !s.isClosed() {
		s.pumpErr.Store(msg)
		s.dead.Store(true)
	}
	conn.Close()
}

func (s *session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *session) adapterToPipe(conn net.Conn) string {
	batch := s.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, MaxFrame)
	}
	sizes := make([]int, batch)
	for {
		n, err := s.dev.Read(bufs, sizes, 0)
		for i := 0; i < n; i++ {
			if werr := WriteFrame(conn, bufs[i][:sizes[i]]); werr != nil && !errors.Is(werr, errFrame) {
				return "The app closed the home link."
			}
		}
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			return "The Cybervulcan adapter went away."
		}
	}
}

func (s *session) pipeToAdapter(conn net.Conn) string {
	buf := make([]byte, MaxFrame)
	for {
		n, err := ReadFrame(conn, buf)
		if err != nil {
			return "The app closed the home link."
		}
		if _, err := s.dev.Write([][]byte{buf[:n]}, 0); err != nil {
			return "The Cybervulcan adapter went away."
		}
	}
}

func configureAdapter(luid winipcfg.LUID, plan Plan) error {
	routes := make([]*winipcfg.RouteData, 0, len(plan.Routes))
	for _, p := range plan.Routes {
		nh := netip.IPv4Unspecified()
		if p.Addr().Is6() {
			nh = netip.IPv6Unspecified()
		}
		routes = append(routes, &winipcfg.RouteData{Destination: p, NextHop: nh, Metric: 0})
	}
	if err := luid.SetIPAddressesForFamily(windows.AF_INET, plan.Addresses); err != nil {
		return fmt.Errorf("set adapter address: %w", err)
	}
	if err := luid.SetRoutesForFamily(windows.AF_INET, routes); err != nil {
		return fmt.Errorf("set routes: %w", err)
	}
	// IPv6 (everything mode: catch-all into the adapter). Best effort: when
	// IPv6 is turned off on this PC these fail, and nothing can leak anyway.
	_ = luid.SetIPAddressesForFamily(windows.AF_INET6, plan.Addresses)
	_ = luid.SetRoutesForFamily(windows.AF_INET6, routes)

	for _, fam := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		iface, err := luid.IPInterface(fam)
		if err != nil {
			if fam == windows.AF_INET6 {
				continue
			}
			return fmt.Errorf("adapter settings: %w", err)
		}
		if fam == windows.AF_INET || plan.MTU >= 1280 {
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
	// v2.2.1: everything mode - all lookups to the adapter's resolver only
	// (no DNS out the Wi-Fi's own servers). Home mode: no rule.
	if plan.Mode == ModeEverything {
		if err := setDNSLock(plan.DNS); err != nil {
			return fmt.Errorf("DNS lock: %w", err)
		}
	} else {
		clearDNSLock()
	}
	return nil
}

// defaultRoute finds the PC's current default route for family, ignoring
// our adapter.
func (s *session) defaultRoute(fam winipcfg.AddressFamily) (RouteCandidate, error) {
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

// pinBypass (re)creates a host route via the current default gateway for
// every bypass address. Called at start and when the PC's network changes.
func (s *session) pinBypass() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var firstErr error
	for _, a := range s.plan.Bypass {
		fam := winipcfg.AddressFamily(windows.AF_INET)
		if a.Is6() {
			fam = windows.AF_INET6
		}
		best, err := s.defaultRoute(fam)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		want := HostRoute{Dest: HostPrefix(a), NextHop: best.NextHop, LUID: best.LUID}
		if old, ok := s.hostRoutes[a]; ok && old == want {
			continue
		}
		if err := winipcfg.LUID(want.LUID).AddRoute(want.Dest, want.NextHop, 0); err != nil &&
			!errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
			if firstErr == nil {
				firstErr = fmt.Errorf("route to %s via the normal network: %w", a, err)
			}
			continue
		}
		if old, ok := s.hostRoutes[a]; ok {
			_ = winipcfg.LUID(old.LUID).DeleteRoute(old.Dest, old.NextHop)
		}
		s.hostRoutes[a] = want
	}
	list := make([]HostRoute, 0, len(s.hostRoutes))
	for _, h := range s.hostRoutes {
		list = append(list, h)
	}
	saveHostRoutes(list)
	return firstErr
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
	s.repin = time.AfterFunc(2*time.Second, func() { _ = s.pinBypass() })
}

func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	mon := s.monitor
	s.monitor = nil
	if s.repin != nil {
		s.repin.Stop()
		s.repin = nil
	}
	if s.stopListen != nil {
		s.stopListen()
		s.stopListen = nil
	}
	pkt := s.pkt
	routes := s.hostRoutes
	s.hostRoutes = map[netip.Addr]HostRoute{}
	s.mu.Unlock()

	if mon != nil {
		_ = mon.Unregister()
	}
	// Before the adapter goes: lookups must not point at a resolver that no
	// longer exists (no internet names until the next start).
	clearDNSLock()
	if pkt != nil {
		_ = pkt.Close()
	}
	// Closing a Wintun adapter that this process created deletes it, and
	// with it its addresses, routes and DNS servers.
	if s.dev != nil {
		_ = s.dev.Close()
	}
	for _, hr := range routes {
		_ = winipcfg.LUID(hr.LUID).DeleteRoute(hr.Dest, hr.NextHop)
	}
	saveHostRoutes(nil)
}
