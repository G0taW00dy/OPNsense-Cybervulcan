package vpn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// The "phone" side of the tests is a second user-space netstack whose
// tun.Device is handed to Start: everything the phone sends comes out of
// that device into the Session, exactly like packets from a VpnService fd.

type echoServers struct {
	tcp net.Listener
	udp net.PacketConn
}

func startEcho(t *testing.T) *echoServers {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		pc.Close()
	})
	return &echoServers{tcp: ln, udp: pc}
}

// recordingDialer sends every flow to the local echo servers and records
// what the session asked for.
type recordingDialer struct {
	echo *echoServers
	fail bool

	mu    sync.Mutex
	calls []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, network+" "+address)
	d.mu.Unlock()
	if d.fail {
		return nil, errors.New("far side unreachable")
	}
	var nd net.Dialer
	if network == "udp" {
		return nd.DialContext(ctx, "udp", d.echo.udp.LocalAddr().String())
	}
	return nd.DialContext(ctx, "tcp", d.echo.tcp.Addr().String())
}

func (d *recordingDialer) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.calls...)
}

func startSession(t *testing.T, opts Options, d Dialer) (*Session, *netstack.Net) {
	t.Helper()
	tdev, phone, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Start(tdev, opts, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, phone
}

func TestTCPEcho(t *testing.T) {
	d := &recordingDialer{echo: startEcho(t)}
	s, phone := startSession(t, Options{Allowed: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}, d)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := phone.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("192.168.1.5:5001"))
	if err != nil {
		t.Fatalf("dial through session: %v (stats %+v)", err, s.Stats())
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	msg := bytes.Repeat([]byte("nas-data-"), 20000) // ~180 KB: many segments
	go func() { _, _ = c.Write(msg) }()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echo mismatch")
	}
	if calls := d.seen(); len(calls) != 1 || calls[0] != "tcp 192.168.1.5:5001" {
		t.Fatalf("dialer calls %v", calls)
	}
	st := s.Stats()
	if st.TCPTotal != 1 || st.TCPActive != 1 || st.TxBytes < int64(len(msg)) || st.RxBytes < int64(len(msg)) {
		t.Fatalf("stats %+v", st)
	}
	c.Close()
	waitFor(t, func() bool { return s.Stats().TCPActive == 0 })
}

func TestUDPEcho(t *testing.T) {
	d := &recordingDialer{echo: startEcho(t)}
	s, phone := startSession(t, Options{}, d)
	c, err := phone.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("192.168.1.5:6690"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ { // same flow, several datagrams
		msg := []byte{'p', 'i', 'n', 'g', byte('0' + i)}
		if _, err := c.Write(msg); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("udp echo %d: %v (stats %+v)", i, err, s.Stats())
		}
		if !bytes.Equal(buf[:n], msg) {
			t.Fatalf("udp echo mismatch: %q", buf[:n])
		}
	}
	if calls := d.seen(); len(calls) != 1 || calls[0] != "udp 192.168.1.5:6690" {
		t.Fatalf("dialer calls %v (one flow expected)", calls)
	}
	if st := s.Stats(); st.UDPTotal != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestBlockedPrefix(t *testing.T) {
	d := &recordingDialer{echo: startEcho(t)}
	s, phone := startSession(t, Options{Allowed: []netip.Prefix{netip.MustParsePrefix("192.168.1.5/32")}}, d)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	c, err := phone.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("8.8.8.8:443"))
	if err == nil {
		c.Close()
		t.Fatal("a destination outside the allowed prefixes was connected")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("blocked TCP should be refused at once, took %v (%v)", time.Since(start), err)
	}
	u, err := phone.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("8.8.4.4:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_, _ = u.Write([]byte("quic?"))
	_ = u.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if n, err := u.Read(make([]byte, 16)); err == nil {
		t.Fatalf("blocked UDP got an answer (%d bytes)", n)
	}
	if calls := d.seen(); len(calls) != 0 {
		t.Fatalf("dialer was called for blocked destinations: %v", calls)
	}
	waitFor(t, func() bool { return s.Stats().Blocked >= 2 })
}

func TestDNSRedirect(t *testing.T) {
	d := &recordingDialer{echo: startEcho(t)}
	s, phone := startSession(t, Options{
		DNS:     netip.MustParseAddrPort("10.10.10.254:53"),
		Allowed: []netip.Prefix{netip.MustParsePrefix("10.10.10.254/32")},
	}, d)
	// An app with a hard-coded resolver outside the allowed list.
	u, err := phone.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("1.1.1.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	q := []byte("dns-query")
	if _, err := u.Write(q); err != nil {
		t.Fatal(err)
	}
	_ = u.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := u.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], q) {
		t.Fatalf("dns answer: %q %v (stats %+v)", buf[:n], err, s.Stats())
	}
	if calls := d.seen(); len(calls) != 1 || calls[0] != "udp 10.10.10.254:53" {
		t.Fatalf("DNS was not redirected: %v", calls)
	}
}

func TestDialFailureRefusesConnection(t *testing.T) {
	d := &recordingDialer{echo: startEcho(t), fail: true}
	s, phone := startSession(t, Options{}, d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := phone.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("192.168.1.5:445"))
	if err == nil {
		c.Close()
		t.Fatal("connection accepted although the far side could not be reached")
	}
	st := s.Stats()
	if st.DialErrors != 1 || st.LastError == "" {
		t.Fatalf("stats %+v", st)
	}
}

func TestCloseEndsFlowsAndIsIdempotent(t *testing.T) {
	d := &recordingDialer{echo: startEcho(t)}
	s, phone := startSession(t, Options{}, d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := phone.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("192.168.1.5:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitFor(t, func() bool { return s.Stats().TCPActive == 1 })
	done := make(chan struct{})
	go func() {
		s.Close()
		s.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close hung")
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("Done not closed")
	}
}

func TestUDPIdleTimeout(t *testing.T) {
	d := &recordingDialer{echo: startEcho(t)}
	s, phone := startSession(t, Options{UDPIdleTimeout: 200 * time.Millisecond}, d)
	u, err := phone.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("192.168.1.5:9"))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_, _ = u.Write([]byte("x"))
	waitFor(t, func() bool { return s.Stats().UDPTotal == 1 })
	waitFor(t, func() bool { return s.Stats().UDPActive == 0 })
}

func TestConfigOptions(t *testing.T) {
	o, err := Config{MTU: 1400, DNS: "10.10.10.254", Allowed: []string{"10.10.10.5", "10.10.10.0/24", "0.0.0.0/0"}}.Options()
	if err != nil {
		t.Fatal(err)
	}
	if o.DNS != netip.MustParseAddrPort("10.10.10.254:53") || o.MTU != 1400 || len(o.Allowed) != 3 ||
		o.Allowed[0] != netip.MustParsePrefix("10.10.10.5/32") {
		t.Fatalf("%+v", o)
	}
	if !o.allowed(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("0.0.0.0/0 must allow IPv4")
	}
	if o.allowed(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("0.0.0.0/0 must not allow IPv6")
	}
	for _, bad := range []Config{{MTU: 100}, {DNS: "router"}, {Allowed: []string{"nas"}}} {
		if _, err := bad.Options(); err == nil {
			t.Errorf("%+v: expected an error", bad)
		}
	}
	if p, _ := ParsePrefix("10.10.10.7/24"); p != netip.MustParsePrefix("10.10.10.0/24") {
		t.Fatalf("not masked: %v", p)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}
