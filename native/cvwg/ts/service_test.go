package ts

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %q", s)
	}
	return m
}

func TestServiceRejectsBadConfig(t *testing.T) {
	var s Service
	for _, in := range []string{"", "nope", `{"stateDir":"rel"}`, `{"stateDir":"/tmp/x","hostname":"h","target":"10.0.0.1:443","token":"short"}`} {
		m := decode(t, s.Start(in))
		if m["error"] == nil || m["error"] == "" {
			t.Errorf("Start(%q) = %v, want error", in, m)
		}
	}
	if m := decode(t, s.Status()); m["up"] != false || m["state"] != StateStopped {
		t.Errorf("status after failed starts = %v", m)
	}
}

func TestServiceErrorDoesNotLeakToken(t *testing.T) {
	var s Service
	c := validConfig(t)
	c.Target = "bad target"
	b, _ := json.Marshal(c)
	out := s.Start(string(b))
	if strings.Contains(out, c.Token) {
		t.Fatalf("error leaks the token: %s", out)
	}
}

func TestServiceStoppedStatusAndDown(t *testing.T) {
	var s Service
	s.Down() // nothing running: no-op
	if got := s.Status(); got != `{"up":false,"state":"stopped"}` {
		t.Errorf("status = %s", got)
	}
}

func TestServiceLogoutRemovesOnlyEngineState(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, stateSubdir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateSubdir, "tailscaled.state"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "other-app-file")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var s Service
	if got := s.Logout(`{"stateDir":` + strconvQuote(dir) + `}`); got != `{"ok":true}` {
		t.Fatalf("logout = %s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, stateSubdir)); !os.IsNotExist(err) {
		t.Error("engine state still there")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("logout removed a file outside the engine folder")
	}
	if m := decode(t, s.Logout("")); m["error"] == nil {
		t.Error("logout without state folder or engine should fail")
	}
	if m := decode(t, s.Logout(`{"stateDir":"relative"}`)); m["error"] == nil {
		t.Error("relative state folder accepted")
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestEngineNotStartedCloseAndDial(t *testing.T) {
	c := validConfig(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(c.Options())
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(c.StateDir, stateSubdir)); err != nil || !fi.IsDir() {
		t.Fatalf("state folder not created: %v", err)
	}
	e.Close() // never started
	e.Close()
	if st := e.Status(context.Background(), ""); st.State != StateStopped || st.Up {
		t.Errorf("status after close = %+v", st)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := e.DialContext(ctx, "tcp", c.Target); err == nil {
		t.Error("dial on a closed engine succeeded")
	}
	if _, err := NewEngine(Options{StateDir: "relative", Hostname: "x"}); err == nil {
		t.Error("relative state dir accepted")
	}
}
