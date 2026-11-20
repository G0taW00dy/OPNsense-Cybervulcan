package ts

import (
	"net/netip"
	"strings"

	"tailscale.com/ipn/ipnstate"
)

// Engine states reported to the app.
const (
	StateStopped       = "stopped"        // no engine
	StateStarting      = "starting"       // starting up / connecting to the control server
	StateNeedsLogin    = "needs_login"    // open AuthURL in a browser and sign in
	StateNeedsApproval = "needs_approval" // signed in; an admin must approve the device in the admin console
	StateRunning       = "running"        // on the tailnet
	StateError         = "error"          // see LastError
)

// Status is a snapshot of the engine, as JSON for the app.
type Status struct {
	Up    bool   `json:"up"`
	State string `json:"state"`

	// Port of the loopback forwarder (filled in by the exports layer).
	Port int `json:"port,omitempty"`

	// AuthURL to open in a browser while State is needs_login.
	AuthURL string `json:"authUrl,omitempty"`

	// TailnetIP is this device's 100.x address.
	TailnetIP string `json:"tailnetIp,omitempty"`

	// PeerOnline: the tailnet node that carries the target (owns the IP or
	// advertises a route to it) is connected to the control server. Nil when
	// no such node is in the network map (route not approved yet?).
	PeerOnline *bool `json:"peerOnline,omitempty"`

	// PeerFound: a node carrying the target is in the network map.
	PeerFound bool `json:"peerFound,omitempty"`

	// Direct: packets to that node go peer-to-peer (not through a relay).
	Direct bool `json:"direct,omitempty"`

	// DERP is the relay region code (e.g. "syd") used to reach that node
	// while there is no direct path.
	DERP string `json:"derp,omitempty"`

	// KeyExpiry: when this device's node key expires (unix seconds, 0 = never / unknown).
	KeyExpiry int64 `json:"keyExpiry,omitempty"`

	// Health lists problems the engine reports (plain text from Tailscale).
	Health []string `json:"health,omitempty"`

	LastError string `json:"lastError,omitempty"`
}

// mapBackendState converts an ipn backend state name to our state.
func mapBackendState(s string) string {
	switch s {
	case "Running":
		return StateRunning
	case "NeedsLogin":
		return StateNeedsLogin
	case "NeedsMachineAuth":
		return StateNeedsApproval
	case "Stopped":
		return StateStopped
	default: // NoState, Starting, InUseOtherUser
		return StateStarting
	}
}

// statusFrom builds a Status from the engine's ipnstate.Status. target is
// the forwarder target ("host:port", may be empty).
func statusFrom(st *ipnstate.Status, target string) Status {
	if st == nil {
		return Status{Up: true, State: StateStarting}
	}
	s := Status{Up: true, State: mapBackendState(st.BackendState), Health: st.Health}
	if s.State == StateNeedsLogin {
		s.AuthURL = st.AuthURL
	}
	for _, ip := range st.TailscaleIPs {
		if ip.Is4() {
			s.TailnetIP = ip.String()
			break
		}
	}
	if s.TailnetIP == "" && len(st.TailscaleIPs) > 0 {
		s.TailnetIP = st.TailscaleIPs[0].String()
	}
	if st.Self != nil && st.Self.KeyExpiry != nil && !st.Self.KeyExpiry.IsZero() {
		s.KeyExpiry = st.Self.KeyExpiry.Unix()
	}
	if p := peerFor(st, target); p != nil {
		online := p.Online
		s.PeerFound = true
		s.PeerOnline = &online
		s.Direct = p.CurAddr != ""
		if !s.Direct {
			s.DERP = p.Relay
		}
	}
	return s
}

// peerFor finds the peer that carries target: the one owning the IP, else
// the one advertising (primary) a route containing it, else (for a name) the
// one whose DNS name or host name matches.
func peerFor(st *ipnstate.Status, target string) *ipnstate.PeerStatus {
	host, _, err := SplitTarget(target)
	if err != nil {
		return nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, p := range st.Peer {
			for _, a := range p.TailscaleIPs {
				if a == ip {
					return p
				}
			}
		}
		var best *ipnstate.PeerStatus
		bestBits := -1
		for _, p := range st.Peer {
			if p.PrimaryRoutes == nil {
				continue
			}
			for i := 0; i < p.PrimaryRoutes.Len(); i++ {
				r := p.PrimaryRoutes.At(i)
				if r.Contains(ip) && r.Bits() > bestBits {
					best, bestBits = p, r.Bits()
				}
			}
		}
		return best
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range st.Peer {
		dns := strings.ToLower(strings.TrimSuffix(p.DNSName, "."))
		if dns == name || strings.HasPrefix(dns, name+".") || strings.EqualFold(p.HostName, name) {
			return p
		}
	}
	return nil
}
