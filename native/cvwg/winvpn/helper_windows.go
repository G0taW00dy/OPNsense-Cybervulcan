//go:build windows

package winvpn

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/internal/namedpipe"
	"golang.org/x/sys/windows"
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
	if len(args) == 1 && args[0] == RepairFlag {
		return runRepair()
	}
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
	// v2.2.5 (audit L3): the helper runs with admin rights, so its exe and
	// DLLs must sit where only admins can change them.
	if err := checkTrustedLocation(self); err != nil {
		helperLogf("exit %d: %v", ExitSecurity, err)
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

// checkTrustedLocation refuses to run the helper from anywhere but a folder
// under Program Files (found with the Known Folder API, not environment
// variables a user can change) that is owned by Administrators, SYSTEM or
// TrustedInstaller and is not a link.
func checkTrustedLocation(exe string) error {
	dir := filepath.Dir(exe)
	low := strings.ToLower(filepath.Clean(dir)) + `\`
	under := false
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX64, windows.FOLDERID_ProgramFilesX86} {
		pf, err := windows.KnownFolderPath(id, 0)
		if err == nil && pf != "" && strings.HasPrefix(low, strings.ToLower(filepath.Clean(pf))+`\`) {
			under = true
			break
		}
	}
	if !under {
		return fmt.Errorf("helper is not installed under Program Files (%s)", dir)
	}
	ptr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return fmt.Errorf("install folder: %w", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("install folder is a link")
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("install folder owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("install folder owner: %w", err)
	}
	if !trustedOwner(owner) && !isTrustedInstaller(owner) {
		return fmt.Errorf("install folder is not owned by Administrators, SYSTEM or TrustedInstaller")
	}
	return nil
}

// isTrustedInstaller: NT SERVICE\TrustedInstaller.
func isTrustedInstaller(sid *windows.SID) bool {
	return sid != nil && sid.String() == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

// runRepair removes the DNS lock and saved host routes, then exits. Started
// by the tray app's "Repair DNS" (through the UAC prompt) when a crash or
// power cut left them behind.
func runRepair() int {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return ExitNotElevated
	}
	if self, err := os.Executable(); err != nil || checkTrustedLocation(self) != nil {
		return ExitSecurity
	}
	cleanupStale()
	helperLogf("repair: DNS lock and saved routes removed")
	return 0
}

// RepairStale starts the helper elevated in repair mode and waits for it
// (the user answers a UAC prompt). Called by the tray app.
func RepairStale() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	proc, err := launchElevated(self, RepairFlag)
	if err != nil {
		return err
	}
	if proc == 0 {
		return nil
	}
	defer windows.CloseHandle(proc)
	if _, err := windows.WaitForSingleObject(proc, 60*1000); err != nil {
		return err
	}
	if code, ok := exitedCode(proc); ok && code != 0 {
		return helperExitError(code)
	}
	return nil
}
