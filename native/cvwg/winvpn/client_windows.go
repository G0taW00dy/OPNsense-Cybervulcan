//go:build windows

package winvpn

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/internal/namedpipe"
)

// Client is the tray app's side: it starts the elevated helper on demand
// (UAC prompt), then forwards start / stop / status over the pipe. Start is
// asynchronous because the UAC prompt can take as long as the user wants;
// callers poll Status.
type Client struct {
	// OnPackets is called with the packet pipe once the adapter is up; it
	// runs the VPN core on NewPipeTun(conn, mtu) (exports_vpn_windows.go:
	// vpn_glue's vpnStart). It owns conn from then on.
	OnPackets func(conn net.Conn, mtu int) error
	// OnStop ends the VPN core (and with it the packet pipe).
	OnStop func()

	nonce string

	mu      sync.Mutex
	conn    net.Conn
	rd      *bufio.Reader
	busy    bool // a Start (UAC prompt + adapter set-up) is in flight
	stopReq bool // Stop was called while busy: undo the start when it ends
	last    Status

	ioMu sync.Mutex // one request on the pipe at a time
}

// dialWait is how long the helper may take to open its pipe after the
// prompt was accepted.
const dialWait = 20 * time.Second

// Start validates r, then (in the background) starts the helper if needed
// and asks it to bring the adapter up.
func (c *Client) Start(r StartRequest) error {
	if err := r.Validate(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.busy {
		c.mu.Unlock()
		return errors.New("the home link is already being changed - wait a moment")
	}
	c.busy = true
	c.stopReq = false
	c.last = Status{State: StateStarting, Mode: r.Mode}
	c.mu.Unlock()

	go func() {
		st, err := c.startSync(r)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.busy = false
		if err != nil {
			c.last = Status{State: StateError, Mode: r.Mode, Error: FriendlyError(err)}
			// Let the helper exit: no elevated process stays behind after a
			// failed start (a retry shows the prompt again).
			c.closeLocked()
			return
		}
		c.last = st
		if c.stopReq {
			c.stopReq = false
			c.mu.Unlock()
			c.Stop()
			c.mu.Lock()
		}
	}()
	return nil
}

func (c *Client) startSync(r StartRequest) (Status, error) {
	if err := c.ensureHelper(); err != nil {
		return Status{}, err
	}
	resp, err := c.roundTrip(Request{Op: OpStart, Start: &r}, 60*time.Second)
	if err != nil {
		return Status{}, err
	}
	if !resp.OK {
		return Status{}, errors.New(resp.Error)
	}
	plan, _ := BuildPlan(r)
	if err := c.attachPackets(plan.MTU); err != nil {
		_, _ = c.roundTrip(Request{Op: OpStop}, 15*time.Second)
		return Status{}, err
	}
	return Status{State: StateOn, Mode: r.Mode}, nil
}

// attachPackets connects the packet pipe and hands it to the VPN core.
func (c *Client) attachPackets(mtu int) error {
	c.mu.Lock()
	nonce := c.nonce
	c.mu.Unlock()
	name, err := PacketPipeName(nonce)
	if err != nil {
		return err
	}
	conn, err := dialHelperPipe(name)
	if err != nil {
		return err
	}
	if c.OnPackets == nil {
		conn.Close()
		return errors.New("the home link is not available in this build")
	}
	return c.OnPackets(conn, mtu)
}

// Stop removes the adapter and lets the helper exit (the next Start shows
// the UAC prompt again).
func (c *Client) Stop() {
	if c.OnStop != nil {
		c.OnStop()
	}
	c.mu.Lock()
	connected := c.conn != nil && !c.busy
	c.mu.Unlock()
	if connected {
		_, _ = c.roundTrip(Request{Op: OpStop}, 15*time.Second)
	}
	c.mu.Lock()
	if c.busy {
		// Turned off while the admin prompt / set-up is still running.
		c.stopReq = true
	} else {
		c.closeLocked()
		c.last = Status{State: StateOff}
	}
	c.mu.Unlock()
}

// Status returns the last known state, refreshing it from the helper when
// connected and idle.
func (c *Client) Status() Status {
	c.mu.Lock()
	if c.busy || c.conn == nil {
		st := c.last
		c.mu.Unlock()
		if st.State == "" {
			st.State = StateOff
		}
		return st
	}
	c.mu.Unlock()
	resp, err := c.roundTrip(Request{Op: OpStatus}, 5*time.Second)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		// Helper gone: Wintun removed the adapter with it.
		c.closeLocked()
		c.last = Status{State: StateError, Mode: c.last.Mode, Error: "The home link stopped unexpectedly."}
		return c.last
	}
	if resp.Status != nil {
		c.last = *resp.Status
	}
	return c.last
}

func (c *Client) closeLocked() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.rd = nil
	}
}

func (c *Client) roundTrip(req Request, timeout time.Duration) (Response, error) {
	line, err := EncodeLine(req)
	if err != nil {
		return Response{}, err
	}
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	c.mu.Lock()
	conn, rd := c.conn, c.rd
	c.mu.Unlock()
	if conn == nil {
		return Response{}, errors.New("the helper is not running")
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(line); err != nil {
		return Response{}, err
	}
	out, err := readLine(rd)
	if err != nil {
		return Response{}, err
	}
	return DecodeResponse(out)
}

// ensureHelper starts the elevated helper (UAC prompt) and connects to it.
func (c *Client) ensureHelper() error {
	c.mu.Lock()
	ok := c.conn != nil
	c.mu.Unlock()
	if ok {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sid := tu.User.Sid.String()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	nonce, _ := NewNonce(random)
	args, err := HelperArgs(nonce, sid)
	if err != nil {
		return fmt.Errorf("this Windows account type is not supported: %w", err)
	}
	pipe, _ := PipeName(nonce)

	// Returns once the user answered the prompt (error if they said no).
	proc, err := launchElevated(exe, args)
	if err != nil {
		return err
	}
	if proc != 0 {
		defer windows.CloseHandle(proc)
	}

	conn, err := dialHelperPipeWatching(pipe, proc)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.conn, c.rd, c.nonce = conn, bufio.NewReaderSize(conn, 4096), nonce
	c.mu.Unlock()
	return nil
}

// dialHelperPipe connects to one of the helper's pipes, retrying while the
// helper starts up. The pipe must be owned by Administrators: a pipe
// squatted by a normal process under this name is refused.
func dialHelperPipe(name string) (net.Conn, error) {
	return dialHelperPipeWatching(name, 0)
}

// dialHelperPipeWatching is dialHelperPipe that also watches the helper
// process (proc, may be 0): if it exits first, the error says why.
func dialHelperPipeWatching(name string, proc windows.Handle) (net.Conn, error) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialWait)
	defer cancel()
	var lastErr error
	for {
		conn, err := (&namedpipe.DialConfig{ExpectedOwner: admins, Access: PipeClientAccess}).DialContext(ctx, name)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if code, done := exitedCode(proc); done {
			return nil, helperExitError(code)
		}
		if ctx.Err() != nil {
			msg := "the admin helper did not answer"
			if lastErr != nil && !errors.Is(lastErr, context.DeadlineExceeded) {
				msg += " (" + lastErr.Error() + ")"
			}
			if line := lastHelperLogLine(); line != "" {
				msg += ". Last helper log line: " + line
			}
			return nil, errors.New(msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
