package ts

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/forward"
)

// MaxWait caps Config.WaitMs.
const MaxWait = 30000

// Config is what the app sends to cvts_start (JSON).
type Config struct {
	// StateDir is an app-private, writable directory. The engine keeps its
	// node key and login state in StateDir/tsnet, so later starts are silent.
	StateDir string `json:"stateDir"`

	// Hostname shown in the Tailscale admin console, e.g. "cybervulcan-pixel-8".
	// It is cleaned up to a DNS label (lower case, a-z 0-9 and "-").
	Hostname string `json:"hostname"`

	// Target is the only destination the loopback forwarder dials:
	// "ip:port" (the router's LAN IP through its subnet route, or its
	// tailnet IP) or "name:port" (a MagicDNS name).
	Target string `json:"target"`

	// Token is the base64 access token (32 bytes), as for the WireGuard forwarder.
	Token string `json:"token"`

	// ControlURL is the coordination server; empty = Tailscale's own.
	ControlURL string `json:"controlURL,omitempty"`

	// WaitMs: how long cvts_start may block waiting for the engine to reach
	// running / needs_login (0 = return at once with "starting"; max MaxWait).
	WaitMs int `json:"waitMs,omitempty"`
}

// Options returns the engine options of c (no forwarder parts).
func (c *Config) Options() Options {
	return Options{StateDir: c.StateDir, Hostname: c.Hostname, ControlURL: c.ControlURL}
}

// Validate checks c and normalises Hostname. It returns plain-English errors.
func (c *Config) Validate() error {
	o := c.Options()
	if err := o.validate(); err != nil {
		return err
	}
	c.Hostname = o.Hostname
	if _, _, err := SplitTarget(c.Target); err != nil {
		return err
	}
	if _, err := forward.ParseToken(c.Token); err != nil {
		return err
	}
	if c.WaitMs < 0 || c.WaitMs > MaxWait {
		return fmt.Errorf("waitMs must be 0-%d", MaxWait)
	}
	return nil
}

// Options configure an Engine.
type Options struct {
	StateDir   string
	Hostname   string
	ControlURL string

	// Logf receives verbose engine logs (nil = discarded).
	Logf func(format string, args ...any)
}

func (o *Options) validate() error {
	if strings.TrimSpace(o.StateDir) == "" {
		return errors.New("state folder is missing")
	}
	if !filepath.IsAbs(o.StateDir) {
		return errors.New("state folder must be an absolute path")
	}
	h := CleanHostname(o.Hostname)
	if h == "" {
		return errors.New("device name is missing")
	}
	o.Hostname = h
	if o.ControlURL != "" {
		u, err := url.Parse(o.ControlURL)
		if err != nil || u.Host == "" {
			return errors.New("control server URL is not valid")
		}
		switch u.Scheme {
		case "https":
		case "http":
			// Plain http only for a local test control server.
			if ip, err := netip.ParseAddr(u.Hostname()); !(u.Hostname() == "localhost" || (err == nil && ip.IsLoopback())) {
				return errors.New("control server URL must use https")
			}
		default:
			return errors.New("control server URL must use https")
		}
	}
	return nil
}

// CleanHostname turns s into a DNS label: lower case, a-z, 0-9 and "-",
// no leading/trailing "-", at most 63 characters. "" if nothing is left.
func CleanHostname(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	h := strings.TrimRight(b.String(), "-")
	if len(h) > 63 {
		h = strings.TrimRight(h[:63], "-")
	}
	return h
}

// SplitTarget validates "host:port" and returns its parts.
func SplitTarget(t string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(t))
	if err != nil || h == "" {
		return "", 0, fmt.Errorf("router address %q must be ip:port", t)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("router port in %q must be 1-65535", t)
	}
	if _, err := netip.ParseAddr(h); err != nil {
		// A MagicDNS name: letters, digits, dots and dashes only.
		for _, r := range h {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-') {
				return "", 0, fmt.Errorf("router address %q is not an IP address or name", h)
			}
		}
	}
	return h, n, nil
}
