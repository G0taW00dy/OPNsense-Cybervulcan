package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return m
}

func TestVPNGlueWithoutTunnel(t *testing.T) {
	tdev, phone, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	out := decode(t, vpnStart(tdev, `{"mode":"home","allowed":["10.10.10.5","10.10.10.254/32"],"mtu":1280}`))
	if out["up"] != true {
		t.Fatalf("start: %v", out)
	}
	defer vpnStop()

	// No cvwg_up tunnel: the flow must be refused, not hang.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := phone.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.10.10.5:5001")); err == nil {
		c.Close()
		t.Fatal("connected without a tunnel")
	}
	st := decode(t, vpnStatusJSON())
	if st["up"] != true || st["mode"] != "home" || st["transport"] != "wireguard" || st["transportUp"] != false {
		t.Fatalf("status %v", st)
	}
	if !strings.Contains(st["lastError"].(string), "not connected") {
		t.Fatalf("lastError %v", st["lastError"])
	}
	vpnStop()
	if st := decode(t, vpnStatusJSON()); st["up"] != false {
		t.Fatalf("after stop %v", st)
	}
}

func TestVPNGlueRejectsBadConfig(t *testing.T) {
	for _, cfg := range []string{`{`, `{"allowed":["nas"]}`, `{"transport":"carrier-pigeon"}`} {
		tdev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		out := decode(t, vpnStart(tdev, cfg))
		if out["error"] == nil {
			t.Fatalf("%s: expected an error, got %v", cfg, out)
		}
		if st := decode(t, vpnStatusJSON()); st["up"] != false || st["error"] == nil {
			t.Fatalf("%s: status %v", cfg, st)
		}
	}
}
