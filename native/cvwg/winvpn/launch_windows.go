//go:build windows

package winvpn

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// v2.1.22: the helper is started with ShellExecuteExW so the tray app keeps
// a handle to it. If the helper exits before it opens its pipe, the app can
// say why (its exit code, plus the last line of its log) instead of the
// bare "the admin helper did not answer".

var (
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	errorCancelled        = 1223
)

// shellExecuteInfo is SHELLEXECUTEINFOW (Go lays the fields out like C).
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

// launchElevated runs exe with args through the UAC prompt ("runas") and
// returns the new process's handle (the caller closes it). Returns once the
// user answered the prompt.
func launchElevated(exe, args string) (windows.Handle, error) {
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return 0, err
	}
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  dir,
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	r, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if errno, ok := callErr.(windows.Errno); ok && errno == errorCancelled {
			return 0, fmt.Errorf("operation was canceled by the user")
		}
		return 0, fmt.Errorf("could not start the admin helper: %w", callErr)
	}
	if info.hProcess == 0 {
		// Should not happen with SEE_MASK_NOCLOSEPROCESS; carry on without
		// exit-code reporting.
		return 0, nil
	}
	return info.hProcess, nil
}

// exitedCode reports whether proc has ended, and its exit code.
func exitedCode(proc windows.Handle) (uint32, bool) {
	if proc == 0 {
		return 0, false
	}
	ev, err := windows.WaitForSingleObject(proc, 0)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		return 0, false
	}
	var code uint32
	if err := windows.GetExitCodeProcess(proc, &code); err != nil {
		return 0, false
	}
	return code, true
}

// helperExitError explains an early helper exit for the user.
func helperExitError(code uint32) error {
	msg := HelperExitReason(code)
	if line := lastHelperLogLine(); line != "" {
		msg += " Last helper log line: " + line
	}
	return fmt.Errorf("the admin helper stopped (code %d): %s", code, msg)
}

// lastHelperLogLine returns the last non-empty line of the helper's log.
func lastHelperLogLine() string {
	b, err := os.ReadFile(knownHelperLogPath())
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		return ""
	}
	s := strings.TrimSpace(lines[len(lines)-1])
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
