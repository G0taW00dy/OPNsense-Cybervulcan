// Package ts runs a Tailscale node inside the app with tsnet: user space
// only (gVisor netstack), no TUN device, no VpnService, no admin rights and
// no separate Tailscale app. Login is interactive (the app opens AuthURL in
// a browser); the node key is kept in the app-private state folder, so later
// starts are silent. The node is not ephemeral.
//
// Two ways to use it:
//
//   - the app: cvts_* exports (exports_ts.go) put a loopback forwarder
//     (package forward, same access-token scheme as the WireGuard tunnel) in
//     front of [Engine.DialContext];
//   - other Go code (e.g. a whole-device VPN mode) can use the Engine as a
//     transport: [NewEngine], [Engine.Start], then [Engine.DialContext].
//
// Log upload to Tailscale is turned off (no-logs-no-support mode).
package ts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tsnet"
)

// stateSubdir is the folder (inside Options.StateDir) owned by the engine.
// RemoveState deletes only this folder.
const stateSubdir = "tsnet"

// Engine is one in-app Tailscale node.
type Engine struct {
	opts Options
	srv  *tsnet.Server

	startOnce sync.Once
	ready     chan struct{} // closed when srv.Start has returned
	startErr  error         // set before ready is closed

	mu      sync.Mutex
	lastErr string
	closed  bool
}

// NewEngine validates o and prepares (does not start) an engine.
func NewEngine(o Options) (*Engine, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	dir := filepath.Join(o.StateDir, stateSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create the Tailscale state folder: %w", err)
	}
	// Privacy: no log upload to log.tailscale.com.
	envknob.SetNoLogsNoSupport()
	e := &Engine{opts: o, ready: make(chan struct{})}
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	e.srv = &tsnet.Server{
		Dir:        dir,
		Hostname:   o.Hostname,
		ControlURL: o.ControlURL,
		Ephemeral:  false,
		Logf:       logf,
		UserLogf:   logf,
	}
	return e, nil
}

// Start brings the node up in the background and returns at once. Watch
// [Engine.Status] for running / needs_login. Calling it again does nothing.
func (e *Engine) Start() {
	e.startOnce.Do(func() {
		go func() {
			err := e.srv.Start()
			if err != nil {
				e.setErr(err)
			}
			e.startErr = err
			close(e.ready)
		}()
	})
}

// WaitReady waits until the background start has finished (not until the
// node is logged in) and returns its error.
func (e *Engine) WaitReady(ctx context.Context) error {
	select {
	case <-e.ready:
		return e.startErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Ready reports whether the engine is signed in and running.
func (e *Engine) Ready() bool { return e.isReady() }

func (e *Engine) isReady() bool {
	select {
	case <-e.ready:
		return true
	default:
		return false
	}
}

func (e *Engine) setErr(err error) {
	e.mu.Lock()
	e.lastErr = err.Error()
	e.mu.Unlock()
}

// SetLastError records an error (e.g. from the forwarder) for Status.
func (e *Engine) SetLastError(err error) { e.setErr(err) }

// ErrNotRunning is returned by DialContext while the node is not on the tailnet.
var ErrNotRunning = errors.New("Tailscale is not connected")

// DialContext dials addr ("ip:port" or "magicdns-name:port") through the
// tailnet, including subnet routes advertised by other nodes. It fails fast
// with an error wrapping ErrNotRunning when the node is not running (not
// signed in, waiting for approval, stopped); it waits for a start in progress
// as long as ctx allows.
func (e *Engine) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	e.Start()
	if err := e.WaitReady(ctx); err != nil {
		return nil, err
	}
	if e.isClosed() {
		return nil, net.ErrClosed
	}
	for {
		st := e.Status(ctx, "")
		switch st.State {
		case StateRunning:
			return e.srv.Dial(ctx, network, addr)
		case StateStarting:
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w (still starting)", ErrNotRunning)
			case <-time.After(250 * time.Millisecond):
			}
		case StateNeedsLogin:
			return nil, fmt.Errorf("%w: sign in to Tailscale first", ErrNotRunning)
		case StateNeedsApproval:
			return nil, fmt.Errorf("%w: approve this device in the Tailscale admin console", ErrNotRunning)
		default:
			if st.LastError != "" {
				return nil, fmt.Errorf("%w: %s", ErrNotRunning, st.LastError)
			}
			return nil, ErrNotRunning
		}
	}
}

func (e *Engine) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

// Status reports the engine state. target ("host:port", may be empty) picks
// the peer whose reachability is reported.
func (e *Engine) Status(ctx context.Context, target string) Status {
	e.mu.Lock()
	lastErr, closed := e.lastErr, e.closed
	e.mu.Unlock()
	if closed {
		return Status{State: StateStopped, LastError: lastErr}
	}
	if !e.isReady() {
		return Status{Up: true, State: StateStarting, LastError: lastErr}
	}
	if e.startErr != nil {
		return Status{Up: true, State: StateError, LastError: lastErr}
	}
	lc, err := e.srv.LocalClient()
	if err != nil {
		return Status{Up: true, State: StateError, LastError: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := lc.Status(ctx)
	if err != nil {
		return Status{Up: true, State: StateError, LastError: err.Error()}
	}
	s := statusFrom(st, target)
	s.LastError = lastErr
	return s
}

// AwaitSettled polls Status until the engine is running, needs login (with
// an auth URL), needs approval or failed, or ctx ends; it returns the last
// status either way.
func (e *Engine) AwaitSettled(ctx context.Context, target string) Status {
	for {
		s := e.Status(ctx, target)
		switch {
		case s.State == StateRunning, s.State == StateNeedsApproval, s.State == StateError,
			s.State == StateStopped, s.State == StateNeedsLogin && s.AuthURL != "":
			return s
		}
		select {
		case <-ctx.Done():
			return s
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// Close shuts the node down (its login is kept). Safe to call more than once.
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	e.mu.Unlock()
	if !e.startOnceDone() {
		return
	}
	// tsnet must not be closed while Start runs.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.WaitReady(ctx); err == context.DeadlineExceeded {
		go func() { <-e.ready; _ = e.srv.Close() }()
		return
	}
	_ = e.srv.Close()
}

// startOnceDone reports whether Start was ever called.
func (e *Engine) startOnceDone() bool {
	started := true
	e.startOnce.Do(func() {
		started = false
		close(e.ready) // never started: make WaitReady return
	})
	return started
}

// Logout signs this device out of the tailnet (the control server expires
// its key, best effort), stops the engine and deletes its state.
func (e *Engine) Logout(ctx context.Context) error {
	if e.isReady() && e.startErr == nil && !e.isClosed() {
		if lc, err := e.srv.LocalClient(); err == nil {
			lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = lc.Logout(lctx)
			cancel()
		}
	}
	e.Close()
	return RemoveState(e.opts.StateDir)
}

// RemoveState deletes the engine's state (node key, login) under stateDir.
// Only the engine's own subfolder is removed.
func RemoveState(stateDir string) error {
	if stateDir == "" || !filepath.IsAbs(stateDir) {
		return errors.New("state folder must be an absolute path")
	}
	return os.RemoveAll(filepath.Join(stateDir, stateSubdir))
}
