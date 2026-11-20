package ts

import (
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

func testToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func validConfig(t *testing.T) Config {
	return Config{
		StateDir: filepath.Join(t.TempDir(), "ts"),
		Hostname: "Cybervulcan Pixel 8",
		Target:   "10.10.10.254:443",
		Token:    testToken(t),
	}
}

func TestConfigValidate(t *testing.T) {
	c := validConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c.Hostname != "cybervulcan-pixel-8" {
		t.Errorf("hostname = %q", c.Hostname)
	}

	cases := map[string]func(c *Config){
		"no state dir":       func(c *Config) { c.StateDir = "" },
		"relative state dir": func(c *Config) { c.StateDir = "rel/dir" },
		"no hostname":        func(c *Config) { c.Hostname = " ** " },
		"no target":          func(c *Config) { c.Target = "" },
		"target no port":     func(c *Config) { c.Target = "10.10.10.254" },
		"target bad port":    func(c *Config) { c.Target = "10.10.10.254:70000" },
		"target port zero":   func(c *Config) { c.Target = "10.10.10.254:0" },
		"target bad name":    func(c *Config) { c.Target = "rou ter:443" },
		"short token":        func(c *Config) { c.Token = base64.StdEncoding.EncodeToString([]byte("short")) },
		"token not base64":   func(c *Config) { c.Token = "%%%" },
		"control http":       func(c *Config) { c.ControlURL = "http://controlplane.example.com" },
		"control ftp":        func(c *Config) { c.ControlURL = "ftp://controlplane.example.com" },
		"control garbage":    func(c *Config) { c.ControlURL = "::::" },
		"wait negative":      func(c *Config) { c.WaitMs = -1 },
		"wait too long":      func(c *Config) { c.WaitMs = MaxWait + 1 },
	}
	for name, mutate := range cases {
		c := validConfig(t)
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), c.Token) && c.Token != "" {
			t.Errorf("%s: error leaks the token", name)
		}
	}

	ok := map[string]func(c *Config){
		"tailnet ip":        func(c *Config) { c.Target = "100.101.102.103:443" },
		"ipv6":              func(c *Config) { c.Target = "[fd7a:115c:a1e0::1]:443" },
		"magicdns":          func(c *Config) { c.Target = "router.tail1234.ts.net:8443" },
		"https control":     func(c *Config) { c.ControlURL = "https://headscale.example.com" },
		"loopback control":  func(c *Config) { c.ControlURL = "http://127.0.0.1:8080" },
		"localhost control": func(c *Config) { c.ControlURL = "http://localhost:8080" },
		"wait max":          func(c *Config) { c.WaitMs = MaxWait },
	}
	for name, mutate := range ok {
		c := validConfig(t)
		mutate(&c)
		if err := c.Validate(); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

func TestCleanHostname(t *testing.T) {
	for in, want := range map[string]string{
		"cybervulcan-pc":               "cybervulcan-pc",
		"Office_PC's #2!":              "office-pc-s-2",
		"  --Phone--  ":                "phone",
		"Ünïcode":                      "n-code",
		"***":                          "",
		strings.Repeat("a", 70):        strings.Repeat("a", 63),
		strings.Repeat("a", 62) + "-b": strings.Repeat("a", 62),
	} {
		if got := CleanHostname(in); got != want {
			t.Errorf("CleanHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	h, p, err := SplitTarget(" 10.10.10.254:443 ")
	if err != nil || h != "10.10.10.254" || p != 443 {
		t.Fatalf("got %q %d %v", h, p, err)
	}
}
