package ts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// End to end against Tailscale's in-process test control server and a local
// DERP relay (no Internet): interactive login via the auth URL, forwarder
// round trip to a fake "router" node, silent restart from saved state, and
// logout. Takes a few seconds; skipped with -short.
func TestIntegrationLoginForwardRestartLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	netns.SetEnabled(false) // no socket marking in tests
	t.Cleanup(func() { netns.SetEnabled(true) })

	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")
	control := &testcontrol.Server{DERPMap: derpMap, RequireAuth: true, AllOnline: true, Logf: logger.Discard}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL := control.HTTPTestServer.URL

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Fake router: another tsnet node echoing on :443.
	router := &tsnet.Server{
		Dir: t.TempDir(), ControlURL: controlURL, Hostname: "router",
		Store: new(mem.Store), Ephemeral: true, Logf: logger.Discard, UserLogf: logger.Discard,
	}
	t.Cleanup(func() { _ = router.Close() })
	if err := router.Start(); err != nil {
		t.Fatal(err)
	}
	approve(ctx, t, control, router)
	rst, err := router.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var routerIP string
	for _, ip := range rst.TailscaleIPs {
		if ip.Is4() {
			routerIP = ip.String()
		}
	}
	ln, err := router.Listen("tcp", ":443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	stateDir := t.TempDir()
	tok := make([]byte, 32)
	for i := range tok {
		tok[i] = byte(i * 7)
	}
	cfg := Config{
		StateDir: stateDir, Hostname: "cybervulcan-test", Target: net.JoinHostPort(routerIP, "443"),
		Token: base64.StdEncoding.EncodeToString(tok), ControlURL: controlURL, WaitMs: 20000,
	}
	cfgJSON, _ := json.Marshal(cfg)

	var svc Service
	t.Cleanup(svc.Down)

	// 1. First start: needs login, with an auth URL and a forwarder port.
	st := parseStatus(t, svc.Start(string(cfgJSON)))
	if st.State != StateNeedsLogin || st.AuthURL == "" || st.Port == 0 {
		t.Fatalf("first start: %+v", st)
	}
	// While not signed in the forwarder fails fast and says why.
	if echo(t, st.Port, tok, "x", 3*time.Second) {
		t.Fatal("forwarder worked before login")
	}
	// 2. The user signs in in the browser.
	if !control.CompleteAuth(st.AuthURL) {
		t.Fatalf("control did not know auth URL %s", st.AuthURL)
	}
	st = waitState(ctx, t, &svc, StateRunning)
	if st.TailnetIP == "" || !st.PeerFound {
		t.Errorf("running status: %+v", st)
	}
	// 3. App -> forwarder -> tailnet -> router and back.
	if !echo(t, st.Port, tok, "ping through tailscale", 15*time.Second) {
		t.Fatal("no echo through the forwarder")
	}
	// Wrong token: dropped.
	if echo(t, st.Port, make([]byte, 32), "x", 3*time.Second) {
		t.Fatal("wrong token was forwarded")
	}
	// Same settings again: keeps the engine (same port).
	if again := parseStatus(t, svc.Start(string(cfgJSON))); again.Port != st.Port || again.State != StateRunning {
		t.Errorf("restart with same settings: %+v", again)
	}

	// 4. Stop and start again: silent login from saved state.
	svc.Down()
	if got := parseStatus(t, svc.Status()); got.State != StateStopped {
		t.Errorf("after down: %+v", got)
	}
	st = parseStatus(t, svc.Start(string(cfgJSON)))
	if st.State != StateRunning {
		st = waitState(ctx, t, &svc, StateRunning)
	}
	if st.AuthURL != "" {
		t.Errorf("second start asked to log in again: %+v", st)
	}
	if !echo(t, st.Port, tok, "again", 15*time.Second) {
		t.Fatal("no echo after restart")
	}

	// 5. Logout deletes the saved login.
	if got := svc.Logout(""); got != `{"ok":true}` {
		t.Fatalf("logout: %s", got)
	}
	if _, err := os.Stat(filepath.Join(stateDir, stateSubdir)); !os.IsNotExist(err) {
		t.Error("state still on disk after logout")
	}
}

// approve completes the interactive login of a plain tsnet node.
func approve(ctx context.Context, t *testing.T, control *testcontrol.Server, s *tsnet.Server) {
	t.Helper()
	lc, err := s.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil {
		st, err := lc.StatusWithoutPeers(ctx)
		if err == nil && st.AuthURL != "" && control.CompleteAuth(st.AuthURL) {
			return
		}
		if err == nil && st.BackendState == "Running" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("router node never got an auth URL")
}

func parseStatus(t *testing.T, s string) Status {
	t.Helper()
	var st Status
	if err := json.Unmarshal([]byte(s), &st); err != nil {
		t.Fatalf("bad status json %q", s)
	}
	return st
}

func waitState(ctx context.Context, t *testing.T, svc *Service, want string) Status {
	t.Helper()
	var st Status
	for ctx.Err() == nil {
		st = parseStatus(t, svc.Status())
		if st.State == want {
			return st
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("never reached %s; last %+v", want, st)
	return st
}

// echo sends token+msg to the forwarder and reports whether msg came back.
func echo(t *testing.T, port int, token []byte, msg string, timeout time.Duration) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(append(append([]byte(nil), token...), msg...)); err != nil {
		return false
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return false
	}
	return bytes.Equal(got, []byte(msg))
}
