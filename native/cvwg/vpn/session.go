package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	// Headroom kept in front of packets handed to the tun.Device (some
	// implementations, e.g. Linux with virtio headers, write into it).
	tunOffset = 16
	// DNS flows are one query/answer: end them quickly.
	dnsIdle = 10 * time.Second
)

// Session is one running VPN interface. Create it with Start.
type Session struct {
	dev  tun.Device
	opts Options
	d    Dialer

	stack *stack.Stack
	ep    *channel.Endpoint

	ctx    context.Context
	cancel context.CancelFunc

	c       counters
	started time.Time

	mu      sync.Mutex
	lastErr string
	flows   map[net.Conn]struct{}
	closed  bool
	wg      sync.WaitGroup // inbound + outbound pumps
	flowWG  sync.WaitGroup // running flows (Add only under mu while !closed)
}

// Start runs a netstack on dev and forwards every TCP and UDP flow to d.
// The Session owns dev from now on: Close closes it.
func Start(dev tun.Device, opts Options, d Dialer) (*Session, error) {
	if dev == nil || d == nil {
		return nil, errors.New("vpn: device and dialer are required")
	}
	opts = opts.withDefaults()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		dev:     dev,
		opts:    opts,
		d:       d,
		ctx:     ctx,
		cancel:  cancel,
		started: time.Now(),
		flows:   map[net.Conn]struct{}{},
	}
	if err := s.setupStack(); err != nil {
		cancel()
		return nil, err
	}
	s.wg.Add(2)
	go s.inbound()
	go s.outbound()
	return s, nil
}

func (s *Session) setupStack() error {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(512, uint32(s.opts.MTU), "")
	if err := st.CreateNIC(nicID, ep); err != nil {
		st.Close()
		return fmt.Errorf("vpn: create NIC: %v", err)
	}
	// Accept packets for every destination address and answer from it.
	if err := st.SetPromiscuousMode(nicID, true); err != nil {
		st.Close()
		return fmt.Errorf("vpn: promiscuous mode: %v", err)
	}
	if err := st.SetSpoofing(nicID, true); err != nil {
		st.Close()
		return fmt.Errorf("vpn: spoofing: %v", err)
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	sack := tcpip.TCPSACKEnabled(true)
	_ = st.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	tcpFwd := tcp.NewForwarder(st, 0, 1024, s.handleTCP)
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(st, s.handleUDP)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	s.stack, s.ep = st, ep
	return nil
}

// inbound: OS -> tun.Device -> netstack.
func (s *Session) inbound() {
	defer s.wg.Done()
	defer s.cancel() // device gone: the whole session ends
	batch := s.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, tunOffset+s.opts.MTU+64)
	}
	sizes := make([]int, batch)
	for {
		n, err := s.dev.Read(bufs, sizes, tunOffset)
		for i := 0; i < n; i++ {
			s.injectPacket(bufs[i][tunOffset : tunOffset+sizes[i]])
		}
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			if s.ctx.Err() == nil {
				s.setErr(fmt.Errorf("interface read: %v", err))
			}
			return
		}
	}
}

func (s *Session) injectPacket(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < header.IPv4MinimumSize {
			return
		}
		// ICMP: dropped (see package doc).
		if pkt[9] == uint8(header.ICMPv4ProtocolNumber) {
			return
		}
		proto = header.IPv4ProtocolNumber
	case 6:
		if len(pkt) < header.IPv6MinimumSize {
			return
		}
		if pkt[6] == uint8(header.ICMPv6ProtocolNumber) {
			return
		}
		proto = header.IPv6ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
	})
	s.ep.InjectInbound(proto, pb)
	pb.DecRef()
}

// outbound: netstack -> tun.Device -> OS.
func (s *Session) outbound() {
	defer s.wg.Done()
	buf := make([]byte, tunOffset+s.opts.MTU+64)
	for {
		pkt := s.ep.ReadContext(s.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		n, _ := view.Read(buf[tunOffset:])
		view.Release()
		if n == 0 {
			continue
		}
		if _, err := s.dev.Write([][]byte{buf[:tunOffset+n]}, tunOffset); err != nil {
			if s.ctx.Err() != nil {
				return
			}
			s.setErr(fmt.Errorf("interface write: %v", err))
		}
	}
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}

func (s *Session) setErr(err error) {
	s.mu.Lock()
	s.lastErr = err.Error()
	s.mu.Unlock()
}

// track registers a flow's two connections so Close can end them. False
// once the session is closing.
func (s *Session) track(app, far net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.flows[app] = struct{}{}
	s.flows[far] = struct{}{}
	s.flowWG.Add(1)
	return true
}

func (s *Session) untrack(app, far net.Conn) {
	s.mu.Lock()
	delete(s.flows, app)
	delete(s.flows, far)
	s.mu.Unlock()
	s.flowWG.Done()
}

func (s *Session) dial(network string, dst netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.opts.DialTimeout)
	defer cancel()
	c, err := s.d.DialContext(ctx, network, dst.String())
	if err != nil {
		s.c.dialErrors.Add(1)
		s.setErr(fmt.Errorf("%s %s: %v", network, dst, err))
		return nil, err
	}
	return c, nil
}

// handleTCP runs in its own goroutine per SYN (tcp.Forwarder starts it).
func (s *Session) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := addrPort(id.LocalAddress, id.LocalPort)
	if !s.opts.allowed(dst.Addr()) {
		s.c.blocked.Add(1)
		r.Complete(true) // RST
		return
	}
	far, err := s.dial("tcp", s.opts.target(dst))
	if err != nil {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		r.Complete(true)
		_ = far.Close()
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	app := gonet.NewTCPConn(&wq, ep)
	s.runFlow(app, far, s.opts.TCPIdleTimeout, true, &s.c.tcpActive, &s.c.tcpTotal)
}

// handleUDP is called for the first packet of every new UDP flow.
// handleUDP always reports the packet as handled (true): blocked flows are
// dropped silently rather than answered with ICMP.
func (s *Session) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := addrPort(id.LocalAddress, id.LocalPort)
	if !s.opts.allowed(dst.Addr()) && !(s.opts.DNS.IsValid() && dst.Port() == 53) {
		s.c.blocked.Add(1)
		return true // dropped
	}
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		return true
	}
	app := gonet.NewUDPConn(&wq, ep)
	idle := s.opts.UDPIdleTimeout
	if dst.Port() == 53 && idle > dnsIdle {
		idle = dnsIdle
	}
	go func() {
		far, err := s.dial("udp", s.opts.target(dst))
		if err != nil {
			_ = app.Close()
			return
		}
		s.runFlow(app, far, idle, false, &s.c.udpActive, &s.c.udpTotal)
	}()
	return true
}

func (s *Session) runFlow(app, far net.Conn, idle time.Duration, halfClose bool, active, total interface{ Add(int64) int64 }) {
	if !s.track(app, far) {
		_ = app.Close()
		_ = far.Close()
		return
	}
	defer s.untrack(app, far)
	active.Add(1)
	total.Add(1)
	relay(app, far, idle, &s.c, halfClose)
	active.Add(-1)
}

// Stats returns the current counters.
func (s *Session) Stats() Stats {
	st := Stats{
		TCPActive:  s.c.tcpActive.Load(),
		TCPTotal:   s.c.tcpTotal.Load(),
		UDPActive:  s.c.udpActive.Load(),
		UDPTotal:   s.c.udpTotal.Load(),
		TxBytes:    s.c.tx.Load(),
		RxBytes:    s.c.rx.Load(),
		Blocked:    s.c.blocked.Load(),
		DialErrors: s.c.dialErrors.Load(),
		Started:    s.started.Unix(),
	}
	s.mu.Lock()
	st.LastError = s.lastErr
	s.mu.Unlock()
	return st
}

// Done is closed when the session has ended (Close, or the device went away).
func (s *Session) Done() <-chan struct{} { return s.ctx.Done() }

// Close ends every flow, stops the netstack and closes the device.
// Safe to call more than once.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	flows := make([]net.Conn, 0, len(s.flows))
	for c := range s.flows {
		flows = append(flows, c)
	}
	s.mu.Unlock()

	s.cancel()
	for _, c := range flows {
		_ = c.Close()
	}
	err := s.dev.Close()
	s.ep.Close()
	s.stack.Close()
	s.wg.Wait()
	s.flowWG.Wait()
	s.stack.Wait()
	return err
}

// String describes the session without addresses of flows (for logs).
func (s *Session) String() string {
	return "vpn.Session(mtu " + strconv.Itoa(s.opts.MTU) + ")"
}
