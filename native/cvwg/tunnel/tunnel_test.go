package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func keypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// fakeRouter is a second user-space WireGuard peer standing in for the home
// router: tunnel address 10.10.99.1 plus the router LAN address
// 10.10.10.254, with an echo server on 10.10.10.254:443.
type fakeRouter struct {
	dev  *device.Device
	port int
	pub  []byte
}

func startFakeRouter(t *testing.T, peerPub, psk []byte) *fakeRouter {
	t.Helper()
	priv, pub := keypair(t)
	tdev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.10.99.1"), netip.MustParseAddr("10.10.10.254")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "router: "))
	// Find a free UDP port for the router's listen port.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.10.99.2/32\n",
		hex.EncodeToString(priv), port, hex.EncodeToString(peerPub))
	if psk != nil {
		cfg += "preshared_key=" + hex.EncodeToString(psk) + "\n"
	}
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	ln, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.10.10.254:443"))
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
	t.Cleanup(func() {
		ln.Close()
		dev.Close()
	})
	return &fakeRouter{dev: dev, port: port, pub: pub}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func newToken(t *testing.T) []byte {
	tok := make([]byte, TokenSize)
	if _, err := rand.Read(tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestForwarderReachesRouterThroughTunnel(t *testing.T) {
	appPriv, appPub := keypair(t)
	psk := newToken(t)
	r := startFakeRouter(t, appPub, psk)
	tok := newToken(t)

	tun, err := Start(Config{
		PrivateKey:          b64(appPriv),
		PeerPublicKey:       b64(r.pub),
		PresharedKey:        b64(psk),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", r.port),
		Address:             "10.10.99.2/32",
		AllowedIPs:          []string{"10.10.10.254/32"},
		PersistentKeepalive: 25,
		Target:              "10.10.10.254:443",
		Token:               b64(tok),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port()), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	msg := []byte("hello router")
	if _, err := c.Write(append(append([]byte{}, tok...), msg...)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("no echo through tunnel: %v (status %+v)", err, tun.Status())
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
	st := tun.Status()
	if st.LastHandshake == 0 || st.RxBytes == 0 || st.TxBytes == 0 {
		t.Fatalf("status not updated: %+v", st)
	}
}

func TestForwarderRejectsWrongToken(t *testing.T) {
	appPriv, appPub := keypair(t)
	r := startFakeRouter(t, appPub, nil)
	tun, err := Start(Config{
		PrivateKey:    b64(appPriv),
		PeerPublicKey: b64(r.pub),
		Endpoint:      fmt.Sprintf("127.0.0.1:%d", r.port),
		Address:       "10.10.99.2",
		AllowedIPs:    []string{"10.10.10.254"},
		Target:        "10.10.10.254:443",
		Token:         b64(newToken(t)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tun.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write(append(newToken(t), []byte("hello")...))
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err == nil {
		t.Fatalf("forwarder answered a client with the wrong token: %q", buf[:n])
	}
	if st := tun.Status(); st.TxBytes != 0 && st.LastHandshake != 0 {
		// A wrong token must never cause traffic into the tunnel.
		t.Fatalf("tunnel was used: %+v", st)
	}
}

func TestConfigValidation(t *testing.T) {
	_, pub := keypair(t)
	priv, _ := keypair(t)
	ok := Config{
		PrivateKey: b64(priv), PeerPublicKey: b64(pub), Endpoint: "203.0.113.5:51820",
		Address: "10.10.99.2/32", AllowedIPs: []string{"10.10.10.254/32"},
		Target: "10.10.10.254:443", Token: b64(newToken(t)),
	}
	cases := map[string]func(c *Config){
		"private key":  func(c *Config) { c.PrivateKey = "nope" },
		"public key":   func(c *Config) { c.PeerPublicKey = "" },
		"endpoint":     func(c *Config) { c.Endpoint = "home.example.com:51820" },
		"allowed IP":   func(c *Config) { c.AllowedIPs = []string{"x"} },
		"address":      func(c *Config) { c.Address = "" },
		"target":       func(c *Config) { c.Target = "10.10.10.254" },
		"access token": func(c *Config) { c.Token = b64([]byte("short")) },
	}
	for want, mutate := range cases {
		c := ok
		mutate(&c)
		tun, err := Start(c)
		if err == nil {
			tun.Close()
			t.Errorf("%s: expected an error", want)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q does not mention it", want, err)
		}
	}
	uapi, err := uapiConfig(&ok)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uapi, ok.PrivateKey) {
		t.Fatal("uapi must use hex keys")
	}
	if !strings.Contains(uapi, "allowed_ip=10.10.10.254/32\n") {
		t.Fatalf("allowed IP missing: %s", uapi)
	}
}
