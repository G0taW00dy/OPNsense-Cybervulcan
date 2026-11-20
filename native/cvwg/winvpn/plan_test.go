package winvpn

import (
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// testKey is a freshly generated 32-byte value (not a real key).
func testKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func baseRequest(t *testing.T, mode string) StartRequest {
	return StartRequest{
		Mode:          mode,
		PrivateKey:    testKey(t),
		PeerPublicKey: testKey(t),
		Endpoint:      "203.0.113.7:51830",
		Address:       "10.10.99.2/32",
		RouterIP:      "10.10.10.254",
		Keepalive:     25,
	}
}

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func TestPlanHome(t *testing.T) {
	r := baseRequest(t, ModeHome)
	r.HomeCIDRs = []string{"10.10.10.20", "192.168.50.0/24", "10.10.10.254/32", "192.168.50.9/24"}
	p, err := BuildPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	want := prefixes("10.10.10.254/32", "10.10.10.20/32", "192.168.50.0/24")
	if !reflect.DeepEqual(p.Routes, want) {
		t.Errorf("routes = %v, want %v", p.Routes, want)
	}
	if !reflect.DeepEqual(p.AllowedIPs, want) {
		t.Errorf("allowed = %v", p.AllowedIPs)
	}
	if len(p.DNS) != 0 || p.LowMetric {
		t.Errorf("home mode must not touch DNS / metric: %+v", p)
	}
	if p.EndpointRoute {
		t.Error("endpoint is outside the home routes: no host route needed")
	}
	if !reflect.DeepEqual(p.Addresses, prefixes("10.10.99.2/32")) {
		t.Errorf("addresses = %v", p.Addresses)
	}
	if p.MTU != defaultMTU {
		t.Errorf("mtu = %d", p.MTU)
	}
}

func TestPlanHomeRouterOnly(t *testing.T) {
	p, err := BuildPlan(baseRequest(t, ModeHome))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Routes, prefixes("10.10.10.254/32")) {
		t.Errorf("routes = %v", p.Routes)
	}
}

func TestPlanHomeEndpointInsideRoutes(t *testing.T) {
	r := baseRequest(t, ModeHome)
	r.Endpoint = "192.168.50.1:51830"
	r.HomeCIDRs = []string{"192.168.50.0/24"}
	p, err := BuildPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	if !p.EndpointRoute || p.EndpointHostRoute() != netip.MustParsePrefix("192.168.50.1/32") {
		t.Errorf("want a host route for the endpoint, got %v %v", p.EndpointRoute, p.EndpointHostRoute())
	}
}

func TestPlanEverything(t *testing.T) {
	p, err := BuildPlan(baseRequest(t, ModeEverything))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Routes, prefixes("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")) {
		t.Errorf("routes = %v", p.Routes)
	}
	if !reflect.DeepEqual(p.DNS, []netip.Addr{netip.MustParseAddr("10.10.10.254")}) {
		t.Errorf("dns = %v", p.DNS)
	}
	if !p.LowMetric || !p.EndpointRoute {
		t.Errorf("everything needs low metric + endpoint host route: %+v", p)
	}
	if p.EndpointHostRoute() != netip.MustParsePrefix("203.0.113.7/32") {
		t.Errorf("host route = %v", p.EndpointHostRoute())
	}
	if !reflect.DeepEqual(p.AllowedIPs, prefixes("0.0.0.0/0")) {
		t.Errorf("allowed = %v", p.AllowedIPs)
	}
	// An IPv6 address so the v6 catch-all routes work (no v6 leak).
	if len(p.Addresses) != 2 || !p.Addresses[1].Addr().Is6() {
		t.Errorf("addresses = %v", p.Addresses)
	}
}

func TestPlanEverythingIPv6Endpoint(t *testing.T) {
	r := baseRequest(t, ModeEverything)
	r.Endpoint = "[2001:db8::7]:51830"
	p, err := BuildPlan(r)
	if err != nil {
		t.Fatal(err)
	}
	if !p.EndpointRoute || p.EndpointHostRoute() != netip.MustParsePrefix("2001:db8::7/128") {
		t.Errorf("v6 endpoint host route: %v %v", p.EndpointRoute, p.EndpointHostRoute())
	}
}

func TestPlanRejects(t *testing.T) {
	cases := map[string]func(r *StartRequest){
		"mode app":         func(r *StartRequest) { r.Mode = "app" },
		"mode empty":       func(r *StartRequest) { r.Mode = "" },
		"no private key":   func(r *StartRequest) { r.PrivateKey = "" },
		"short key":        func(r *StartRequest) { r.PeerPublicKey = base64.StdEncoding.EncodeToString([]byte("short")) },
		"bad psk":          func(r *StartRequest) { r.PresharedKey = "not base64!" },
		"endpoint no port": func(r *StartRequest) { r.Endpoint = "203.0.113.7" },
		"endpoint name":    func(r *StartRequest) { r.Endpoint = "router.example.com:51830" },
		"endpoint port 0":  func(r *StartRequest) { r.Endpoint = "203.0.113.7:0" },
		"endpoint lo":      func(r *StartRequest) { r.Endpoint = "127.0.0.1:51830" },
		"address v6":       func(r *StartRequest) { r.Address = "fd00::2/128" },
		"address junk":     func(r *StartRequest) { r.Address = "C:\\Windows" },
		"router range":     func(r *StartRequest) { r.RouterIP = "10.10.10.0/24" },
		"router missing":   func(r *StartRequest) { r.RouterIP = "" },
		"keepalive":        func(r *StartRequest) { r.Keepalive = -1 },
		"mtu low":          func(r *StartRequest) { r.MTU = 100 },
		"mtu high":         func(r *StartRequest) { r.MTU = 9000 },
		"home too wide":    func(r *StartRequest) { r.HomeCIDRs = []string{"10.0.0.0/7"} },
		"home default":     func(r *StartRequest) { r.HomeCIDRs = []string{"0.0.0.0/0"} },
		"home loopback":    func(r *StartRequest) { r.HomeCIDRs = []string{"127.0.0.0/8"} },
		"home multicast":   func(r *StartRequest) { r.HomeCIDRs = []string{"224.0.0.1"} },
		"home link-local":  func(r *StartRequest) { r.HomeCIDRs = []string{"169.254.1.1"} },
		"home v6":          func(r *StartRequest) { r.HomeCIDRs = []string{"fd00::1"} },
		"home junk":        func(r *StartRequest) { r.HomeCIDRs = []string{"nas; rm -rf"} },
		"home too many": func(r *StartRequest) {
			for i := 0; i <= maxHomeCIDRs; i++ {
				r.HomeCIDRs = append(r.HomeCIDRs, "10.10.10.20")
			}
		},
		"long endpoint": func(r *StartRequest) { r.Endpoint = strings.Repeat("1", 200) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := baseRequest(t, ModeHome)
			mutate(&r)
			if _, err := BuildPlan(r); err == nil {
				t.Errorf("accepted %s", r)
			}
		})
	}
}

func TestRequestStringHasNoKeys(t *testing.T) {
	r := baseRequest(t, ModeEverything)
	r.PresharedKey = testKey(t)
	s := r.String()
	for _, k := range []string{r.PrivateKey, r.PeerPublicKey, r.PresharedKey} {
		if strings.Contains(s, k) {
			t.Fatal("String() leaks a key")
		}
	}
}
