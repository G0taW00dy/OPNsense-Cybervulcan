package winvpn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func startLine(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	r := baseRequest(t, ModeHome)
	b, _ := json.Marshal(r)
	var start map[string]any
	_ = json.Unmarshal(b, &start)
	m := map[string]any{"op": OpStart, "start": start}
	if mutate != nil {
		mutate(m)
	}
	out, _ := json.Marshal(m)
	return out
}

func TestDecodeRequestAccepts(t *testing.T) {
	for _, line := range [][]byte{
		[]byte(`{"op":"stop"}`),
		[]byte(`{"op":"status"}` + "\n"),
		startLine(t, nil),
	} {
		if _, err := DecodeRequest(line); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

func TestDecodeRequestRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":          []byte(``),
		"not json":       []byte(`start`),
		"unknown op":     []byte(`{"op":"exec"}`),
		"run command":    []byte(`{"op":"start","cmd":"cmd.exe /c whoami"}`),
		"path field":     []byte(`{"op":"status","path":"C:\\x"}`),
		"two objects":    []byte(`{"op":"stop"}{"op":"stop"}`),
		"stop with args": startLine(t, func(m map[string]any) { m["op"] = OpStop }),
		"start no args":  []byte(`{"op":"start"}`),
		"start unknown field": startLine(t, func(m map[string]any) {
			m["start"].(map[string]any)["dll"] = "evil.dll"
		}),
		"start bad mode": startLine(t, func(m map[string]any) {
			m["start"].(map[string]any)["mode"] = "app"
		}),
		"start bad cidr": startLine(t, func(m map[string]any) {
			m["start"].(map[string]any)["homeCidrs"] = []string{"0.0.0.0/0"}
		}),
		"oversized": []byte(`{"op":"status","x":"` + strings.Repeat("a", MaxMessageBytes) + `"}`),
		"op case":   []byte(`{"op":"STOP"}`),
		"array":     []byte(`[{"op":"stop"}]`),
	}
	for name, line := range cases {
		if _, err := DecodeRequest(line); err == nil {
			t.Errorf("%s: accepted %q", name, line)
		}
	}
}

func TestResponseRoundTrip(t *testing.T) {
	line, err := EncodeLine(Response{V: ProtocolVersion, OK: true, Status: &Status{State: StateOn, Mode: ModeHome, RxBytes: 5}})
	if err != nil {
		t.Fatal(err)
	}
	if line[len(line)-1] != '\n' {
		t.Fatal("no newline")
	}
	r, err := DecodeResponse(line[:len(line)-1])
	if err != nil || !r.OK || r.Status.State != StateOn || r.Status.RxBytes != 5 {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := DecodeResponse([]byte(`{"v":99,"ok":true}`)); err == nil {
		t.Error("accepted other protocol version")
	}
}

func TestPipeNameAndArgs(t *testing.T) {
	n, err := NewNonce(make([]byte, 16))
	if err != nil || !ValidNonce(n) {
		t.Fatal(n, err)
	}
	if _, err := NewNonce(make([]byte, 8)); err == nil {
		t.Error("short nonce accepted")
	}
	name, err := PipeName(n)
	if err != nil || name != `\\.\pipe\Cybervulcan-vpn-`+n {
		t.Fatal(name, err)
	}
	for _, bad := range []string{"", "..\\..\\x", strings.Repeat("g", 32), strings.ToUpper(strings.Repeat("ab", 16))} {
		if _, err := PipeName(bad); err == nil {
			t.Errorf("pipe nonce %q accepted", bad)
		}
	}

	sid := "S-1-5-21-1004336348-1177238915-682003330-1001"
	args, err := HelperArgs(n, sid)
	if err != nil {
		t.Fatal(err)
	}
	gn, gs, err := ParseHelperArgs(strings.Fields(args))
	if err != nil || gn != n || gs != sid {
		t.Fatal(gn, gs, err)
	}
	for _, bad := range [][]string{
		{HelperFlag, n},
		{HelperFlag, n, sid, "extra"},
		{"--other", n, sid},
		{HelperFlag, n, "S-1-5-18"},           // LocalSystem
		{HelperFlag, n, "S-1-5-32-544"},       // Administrators
		{HelperFlag, n, "S-1-1-0"},            // Everyone
		{HelperFlag, n, sid + ")(A;;GA;;;WD"}, // SDDL injection
	} {
		if _, _, err := ParseHelperArgs(bad); err == nil {
			t.Errorf("helper args %q accepted", bad)
		}
	}
	if !ValidUserSID("S-1-12-1-1234567890-1234567890-1234567890-1234567890") {
		t.Error("Entra ID SID refused")
	}
}

func TestPipeSDDL(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	s, err := PipeSDDL(sid)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "O:BA") || !strings.Contains(s, "(A;;0x120083;;;"+sid+")") || !strings.Contains(s, "ML;;NW;;;ME") {
		t.Errorf("sddl = %s", s)
	}
	if strings.Contains(s, ";;GA;;;"+sid) || strings.Contains(s, "WD") {
		t.Errorf("too broad: %s", s)
	}
	if _, err := PipeSDDL("S-1-1-0"); err == nil {
		t.Error("Everyone accepted")
	}
}

func TestFriendlyError(t *testing.T) {
	if !strings.Contains(FriendlyError(errString("The operation was canceled by the user.")), "admin prompt was cancelled") {
		t.Error("UAC cancel not explained")
	}
	if !strings.Contains(FriendlyError(errString("Unable to load library wintun.dll")), "reinstall") {
		t.Error("missing wintun.dll not explained")
	}
	if FriendlyError(nil) != "" {
		t.Error("nil")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestParseStartJSON(t *testing.T) {
	r := baseRequest(t, ModeEverything)
	b, _ := json.Marshal(r)
	got, err := ParseStartJSON(b)
	if err != nil || got.Mode != ModeEverything || got.PrivateKey != r.PrivateKey {
		t.Fatal(err)
	}
	for _, bad := range []string{`{}`, `{"mode":"home","x":1}`, `not json`, string(b) + `{}`} {
		if _, err := ParseStartJSON([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// The Dart side (lib/src/platform/vpn_modes_windows.dart) sends exactly this
// shape; test/vpn_modes_windows_test.dart checks the same fixture.
func TestDartContractFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "fixtures", "home_link_request.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseStartJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(r)
	if err != nil || len(p.Routes) != 3 || r.PresharedKey == "" || r.MTU != 1280 {
		t.Fatalf("%+v %v", p, err)
	}
}
