// Package tunnel runs a WireGuard client entirely in user space (wireguard-go
// on a gVisor netstack). No TUN device, no VpnService and no admin rights are
// needed: the tunnel is only visible to this app.
//
// The app reaches the router through a loopback TCP forwarder:
//
//	app --TCP--> 127.0.0.1:<random port> --netstack/WireGuard--> target (router:443)
//
// Every forwarded connection must start with the 32-byte access token from
// the Config, so other apps or processes on the same device cannot use the
// forwarder. The token is consumed; everything after it (the TLS handshake
// with the router, then HTTP) is relayed unchanged, so the app still checks
// the router's certificate end to end.
package tunnel

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TokenSize is the length of the access token each forwarded connection
// must send first.
const TokenSize = 32

// Config describes one WireGuard peer (the home router) and the single TCP
// target that the forwarder may reach through it.
type Config struct {
	// Base64 WireGuard keys (as in wg-quick files).
	PrivateKey    string `json:"privateKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	PresharedKey  string `json:"presharedKey,omitempty"`

	// Endpoint is "ip:port". The app resolves host names itself so DNS goes
	// through the platform resolver.
	Endpoint string `json:"endpoint"`

	// Address is this app's tunnel address, e.g. "10.10.99.2" or "10.10.99.2/32".
	Address string `json:"address"`

	// AllowedIPs routed into the tunnel, e.g. ["10.10.10.254/32"].
	AllowedIPs []string `json:"allowedIPs"`

	// PersistentKeepalive in seconds (0 = off).
	PersistentKeepalive int `json:"keepalive"`

	// Target is the only destination the forwarder dials, e.g. "10.10.10.254:443".
	Target string `json:"target"`

	// Token is the base64 access token (TokenSize bytes).
	Token string `json:"token"`

	// MTU of the virtual interface (default 1280, safe behind other VPNs).
	MTU int `json:"mtu,omitempty"`
}

// Status is a snapshot of the running tunnel.
type Status struct {
	Up            bool   `json:"up"`
	Port          int    `json:"port"`
	LastHandshake int64  `json:"lastHandshake"` // unix seconds, 0 = never
	RxBytes       int64  `json:"rx"`
	TxBytes       int64  `json:"tx"`
	LastError     string `json:"lastError,omitempty"`
}

// Tunnel is one running user-space WireGuard client plus its forwarder.
type Tunnel struct {
	dev    *device.Device
	tnet   *netstack.Net
	ln     net.Listener
	target netip.AddrPort
	token  []byte

	mu      sync.Mutex
	lastErr string
	closed  bool
	wg      sync.WaitGroup
}

func keyHex(name, b64 string, optional bool) (string, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		if optional {
			return "", nil
		}
		return "", fmt.Errorf("%s is missing", name)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("%s is not a WireGuard key (32 bytes, base64)", name)
	}
	return hex.EncodeToString(raw), nil
}

func parseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

// uapiConfig builds the wireguard-go IPC configuration for c.
func uapiConfig(c *Config) (string, error) {
	priv, err := keyHex("private key", c.PrivateKey, false)
	if err != nil {
		return "", err
	}
	pub, err := keyHex("router public key", c.PeerPublicKey, false)
	if err != nil {
		return "", err
	}
	psk, err := keyHex("pre-shared key", c.PresharedKey, true)
	if err != nil {
		return "", err
	}
	ep, err := netip.ParseAddrPort(strings.TrimSpace(c.Endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint %q must be ip:port", c.Endpoint)
	}
	if len(c.AllowedIPs) == 0 {
		return "", errors.New("allowed IPs are missing")
	}
	if c.PersistentKeepalive < 0 || c.PersistentKeepalive > 65535 {
		return "", errors.New("keepalive out of range")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if psk != "" {
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", ep.String())
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.PersistentKeepalive)
	b.WriteString("replace_allowed_ips=true\n")
	for _, a := range c.AllowedIPs {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			addr, err2 := netip.ParseAddr(strings.TrimSpace(a))
			if err2 != nil {
				return "", fmt.Errorf("allowed IP %q is not an address or CIDR", a)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		fmt.Fprintf(&b, "allowed_ip=%s\n", p.Masked().String())
	}
	return b.String(), nil
}

// Start brings the tunnel up and starts the loopback forwarder. It does not
// wait for a handshake: the first forwarded connection triggers it.
func Start(c Config) (*Tunnel, error) {
	uapi, err := uapiConfig(&c)
	if err != nil {
		return nil, err
	}
	local, err := parseAddr(c.Address)
	if err != nil {
		return nil, fmt.Errorf("tunnel address %q is not valid", c.Address)
	}
	target, err := netip.ParseAddrPort(strings.TrimSpace(c.Target))
	if err != nil {
		return nil, fmt.Errorf("target %q must be ip:port", c.Target)
	}
	token, err := base64.StdEncoding.DecodeString(c.Token)
	if err != nil || len(token) != TokenSize {
		return nil, errors.New("access token must be 32 bytes, base64")
	}
	mtu := c.MTU
	if mtu <= 0 {
		mtu = 1280
	}

	t := &Tunnel{target: target, token: token}
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			t.mu.Lock()
			t.lastErr = fmt.Sprintf(format, args...)
			t.mu.Unlock()
		},
	}

	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{local}, nil, mtu)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard up: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("loopback listener: %w", err)
	}
	t.dev, t.tnet, t.ln = dev, tnet, ln
	t.wg.Add(1)
	go t.acceptLoop()
	return t, nil
}

// Port is the loopback port of the forwarder.
func (t *Tunnel) Port() int { return t.ln.Addr().(*net.TCPAddr).Port }

func (t *Tunnel) acceptLoop() {
	defer t.wg.Done()
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		go t.forward(c)
	}
}

func (t *Tunnel) setErr(err error) {
	t.mu.Lock()
	t.lastErr = err.Error()
	t.mu.Unlock()
}

func (t *Tunnel) forward(c net.Conn) {
	defer c.Close()
	// Access token first, within a few seconds.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, TokenSize)
	if _, err := io.ReadFull(c, got); err != nil {
		return
	}
	if subtle.ConstantTimeCompare(got, t.token) != 1 {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	rc, err := t.tnet.DialContextTCPAddrPort(ctx, t.target)
	cancel()
	if err != nil {
		t.setErr(fmt.Errorf("dial %s through tunnel: %w", t.target, err))
		return
	}
	defer rc.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(rc, c)
		_ = rc.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, rc)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// Status reads handshake time and byte counters from wireguard-go.
func (t *Tunnel) Status() Status {
	s := Status{Up: true, Port: t.Port()}
	if cfg, err := t.dev.IpcGet(); err == nil {
		sc := bufio.NewScanner(strings.NewReader(cfg))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			n, _ := strconv.ParseInt(v, 10, 64)
			switch k {
			case "last_handshake_time_sec":
				s.LastHandshake = n
			case "rx_bytes":
				s.RxBytes = n
			case "tx_bytes":
				s.TxBytes = n
			}
		}
	}
	t.mu.Lock()
	s.LastError = t.lastErr
	t.mu.Unlock()
	return s
}

// Close stops the forwarder and the WireGuard device.
func (t *Tunnel) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	_ = t.ln.Close()
	t.wg.Wait()
	t.dev.Close()
}
