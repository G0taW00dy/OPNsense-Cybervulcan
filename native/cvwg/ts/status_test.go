package ts

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func routes(p ...string) *views.Slice[netip.Prefix] {
	var ps []netip.Prefix
	for _, s := range p {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	v := views.SliceOf(ps)
	return &v
}

func sampleStatus() *ipnstate.Status {
	exp := time.Unix(1_900_000_000, 0)
	return &ipnstate.Status{
		BackendState: "Running",
		TailscaleIPs: []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::5"), netip.MustParseAddr("100.64.0.5")},
		Self:         &ipnstate.PeerStatus{KeyExpiry: &exp},
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{
			key.NewNode().Public(): {
				HostName:      "router",
				DNSName:       "router.tail1234.ts.net.",
				TailscaleIPs:  []netip.Addr{netip.MustParseAddr("100.64.0.1")},
				PrimaryRoutes: routes("10.10.10.254/32"),
				Online:        true,
				Relay:         "syd",
			},
			key.NewNode().Public(): {
				HostName:      "nas",
				TailscaleIPs:  []netip.Addr{netip.MustParseAddr("100.64.0.2")},
				PrimaryRoutes: routes("10.10.10.0/24"),
				Online:        false,
				CurAddr:       "203.0.113.9:41641",
			},
		},
	}
}

func TestStatusFromRunning(t *testing.T) {
	s := statusFrom(sampleStatus(), "10.10.10.254:443")
	if !s.Up || s.State != StateRunning {
		t.Fatalf("state = %+v", s)
	}
	if s.TailnetIP != "100.64.0.5" {
		t.Errorf("tailnet ip = %q (want the IPv4 one)", s.TailnetIP)
	}
	if s.KeyExpiry != 1_900_000_000 {
		t.Errorf("key expiry = %d", s.KeyExpiry)
	}
	// The /32 route beats the /24 one.
	if !s.PeerFound || s.PeerOnline == nil || !*s.PeerOnline || s.Direct || s.DERP != "syd" {
		t.Errorf("peer = found %v online %v direct %v derp %q", s.PeerFound, s.PeerOnline, s.Direct, s.DERP)
	}
	if s.AuthURL != "" {
		t.Error("auth URL reported while running")
	}
}

func TestStatusPeerSelection(t *testing.T) {
	st := sampleStatus()
	// Other LAN host: only the /24 route covers it -> the NAS node (direct, offline).
	s := statusFrom(st, "10.10.10.7:443")
	if !s.PeerFound || *s.PeerOnline || !s.Direct || s.DERP != "" {
		t.Errorf("subnet peer: %+v", s)
	}
	// Tailnet IP of the router.
	if s := statusFrom(st, "100.64.0.1:443"); !s.PeerFound || !*s.PeerOnline {
		t.Errorf("tailnet ip peer: %+v", s)
	}
	// MagicDNS short and full names.
	for _, n := range []string{"router:443", "router.tail1234.ts.net:443"} {
		if s := statusFrom(st, n); !s.PeerFound || s.DERP != "syd" {
			t.Errorf("%s: %+v", n, s)
		}
	}
	// Nobody carries it (route not approved yet).
	s = statusFrom(st, "192.168.1.1:443")
	if s.PeerFound || s.PeerOnline != nil {
		t.Errorf("unknown target: %+v", s)
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "peerOnline") {
		t.Errorf("peerOnline should be omitted: %s", b)
	}
	// No target at all.
	if s := statusFrom(st, ""); s.PeerFound {
		t.Error("peer found without target")
	}
}

func TestStatusStates(t *testing.T) {
	for in, want := range map[string]string{
		"Running": StateRunning, "NeedsLogin": StateNeedsLogin, "NeedsMachineAuth": StateNeedsApproval,
		"Stopped": StateStopped, "Starting": StateStarting, "NoState": StateStarting, "": StateStarting,
	} {
		if got := mapBackendState(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	s := statusFrom(&ipnstate.Status{BackendState: "NeedsLogin", AuthURL: "https://login.example.com/a/123"}, "")
	if s.State != StateNeedsLogin || s.AuthURL != "https://login.example.com/a/123" {
		t.Errorf("needs login: %+v", s)
	}
	if s := statusFrom(nil, ""); s.State != StateStarting {
		t.Errorf("nil status: %+v", s)
	}
}

func TestStatusJSON(t *testing.T) {
	online := true
	b, err := json.Marshal(Status{Up: true, State: StateRunning, Port: 4242, TailnetIP: "100.64.0.5",
		PeerOnline: &online, PeerFound: true, DERP: "syd", KeyExpiry: 5})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"up": true, "state": "running", "port": 4242.0, "tailnetIp": "100.64.0.5",
		"peerOnline": true, "peerFound": true, "derp": "syd", "keyExpiry": 5.0,
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v (json %s)", k, m[k], want, b)
		}
	}
	for _, k := range []string{"authUrl", "lastError", "direct", "health"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s should be omitted when empty: %s", k, b)
		}
	}
	b, _ = json.Marshal(Status{State: StateStopped})
	if string(b) != `{"up":false,"state":"stopped"}` {
		t.Errorf("stopped json = %s", b)
	}
}
