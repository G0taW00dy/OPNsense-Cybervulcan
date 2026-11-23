//go:build windows

package winvpn

import (
	"bufio"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/internal/namedpipe"
)

// How long the helper waits for the tray app to connect (after the UAC
// prompt; after a start reply for the packet pipe), and for each request on
// an idle control connection (status polls arrive
// every few seconds while a mode is on; the tray app never goes silent for
// this long unless it hung).
const (
	acceptTimeout = 30 * time.Second
	idleTimeout   = 10 * time.Minute
)

// RunHelper is the elevated helper's main loop: <exe> --vpn-helper <nonce>
// <user SID>. It serves exactly one verified client and exits when that
// client disconnects (the tray app closed or crashed), removing the adapter
// first. Returns the process exit code.
func RunHelper(args []string) int {
	helperLogf("helper starting (%d args)", len(args))
	// v2.2.1: whatever way the helper ends (including a panic), the DNS lock
	// must not outlive it - names would stop resolving on the PC.
	defer clearDNSLock()
	defer func() {
		if r := recover(); r != nil {
			helperLogf("panic: %v", r)
			clearDNSLock()
			panic(r)
		}
	}()
	nonce, userSID, err := ParseHelperArgs(args)
	if err != nil {
		helperLogf("exit %d: %v", ExitBadArgs, err)
		return ExitBadArgs
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		helperLogf("exit %d: not elevated", ExitNotElevated)
		return ExitNotElevated
	}
	if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && tu.User.Sid.String() != userSID {
		// Windows "Administrator protection" (and over-the-shoulder
		// elevation) runs the helper as a different account. That is
		// fine: the pipe is still only open to the app's user.
		helperLogf("note: running as a different account than the app's user")
	}
	pipe, _ := PipeName(nonce)
	pktPipe, _ := PacketPipeName(nonce)
	sddl, _ := PipeSDDL(userSID)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		helperLogf("exit %d: security descriptor: %v", ExitSecurity, err)
		return ExitSecurity
	}
	wantSID, err := windows.StringToSid(userSID)
	if err != nil {
		helperLogf("exit %d: user SID: %v", ExitSecurity, err)
		return ExitSecurity
	}
	self, err := os.Executable()
	if err != nil {
		helperLogf("exit %d: own path: %v", ExitSecurity, err)
		return ExitSecurity
	}

	cleanupStale()

	ln, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(pipe)
	if err != nil {
		helperLogf("exit %d: create pipe: %v", ExitPipe, err)
		return ExitPipe
	}
	helperLogf("pipe open, waiting for the app")
	conn, err := acceptVerified(ln, wantSID, self)
	ln.Close() // one client only; no further pipe instances
	if err != nil {
		helperLogf("exit %d: %v", ExitNoClient, err)
		return ExitNoClient
	}
	helperLogf("app connected")
	defer conn.Close()

	m := &manager{listenPackets: func() (func() (net.Conn, error), func(), error) {
		pl, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(pktPipe)
		if err != nil {
			return nil, nil, err
		}
		accept := func() (net.Conn, error) { return acceptVerified(pl, wantSID, self) }
		return accept, func() { pl.Close() }, nil
	}}
	defer m.Stop()
	serve(conn, m)
	return 0
}

// acceptVerified waits for the tray app: same user (the SID on the command
// line) and the same exe as this helper.
func acceptVerified(ln net.Listener, wantSID *windows.SID, self string) (net.Conn, error) {
	deadline := time.Now().Add(acceptTimeout)
	type res struct {
		c   net.Conn
		err error
	}
	for time.Now().Before(deadline) {
		ch := make(chan res, 1)
		go func() {
			c, err := ln.Accept()
			ch <- res{c, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				return nil, r.err
			}
			if err := verifyClient(r.c, wantSID, self); err != nil {
				helperLogf("refused a client: %v", err)
				r.c.Close()
				continue
			}
			return r.c, nil
		case <-time.After(time.Until(deadline)):
			return nil, errors.New("no client")
		}
	}
	return nil, errors.New("no client")
}

type handleConn interface{ Handle() windows.Handle }

func verifyClient(c net.Conn, wantSID *windows.SID, self string) error {
	hc, ok := c.(handleConn)
	if !ok {
		return errors.New("not a pipe")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(hc.Handle(), &pid); err != nil {
		return err
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(proc)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(proc, 0, &buf[0], &n); err != nil {
		return err
	}
	if !samePath(windows.UTF16ToString(buf[:n]), self) {
		return errors.New("client is a different program")
	}

	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	if !u.User.Sid.Equals(wantSID) {
		return errors.New("client is a different user")
	}
	return nil
}

func samePath(a, b string) bool {
	if ea, err := filepath.EvalSymlinks(a); err == nil {
		a = ea
	}
	if eb, err := filepath.EvalSymlinks(b); err == nil {
		b = eb
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// serve answers requests until the client disconnects or goes idle.
func serve(conn net.Conn, m *manager) {
	r := bufio.NewReaderSize(conn, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idleTimeout))
		line, err := readLine(r)
		if err != nil {
			return
		}
		resp := handle(line, m)
		out, err := EncodeLine(resp)
		if err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// readLine reads one line of at most MaxMessageBytes.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		line = append(line, chunk...)
		if len(line) > MaxMessageBytes {
			return nil, errors.New("line too long")
		}
		if !isPrefix {
			return line, nil
		}
	}
}

func handle(line []byte, m *manager) Response {
	req, err := DecodeRequest(line)
	if err != nil {
		return Response{V: ProtocolVersion, Error: err.Error()}
	}
	switch req.Op {
	case OpStart:
		if err := m.Start(*req.Start); err != nil {
			st := m.Status()
			return Response{V: ProtocolVersion, Error: err.Error(), Status: &st}
		}
	case OpStop:
		m.Stop()
	}
	st := m.Status()
	return Response{V: ProtocolVersion, OK: true, Status: &st}
}
