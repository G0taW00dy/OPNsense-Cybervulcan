package winvpn

import (
	"fmt"
	"os"
	"path/filepath"
)

// Helper exit codes (RunHelper and windows/runner/vpn_helper.cpp).
const (
	ExitBadArgs      = 2  // command line not as expected
	ExitNotElevated  = 3  // started without admin rights
	ExitSecurity     = 4  // pipe security / own path could not be set up
	ExitPipe         = 5  // the control pipe could not be created
	ExitNoClient     = 6  // the tray app did not connect (or failed the check)
	ExitRunnerPath   = 10 // runner: own exe path unknown
	ExitRunnerDLL    = 11 // runner: cvwg.dll would not load
	ExitRunnerExport = 12 // runner: cvwg.dll has no helper entry point
)

// HelperExitReason explains a helper exit code in plain English.
func HelperExitReason(code uint32) string {
	switch code {
	case 0:
		return "it ended before the app connected."
	case ExitBadArgs:
		return "it was started with the wrong arguments (reinstall Cybervulcan)."
	case ExitNotElevated:
		return "it did not get admin rights."
	case ExitSecurity:
		return "it could not set up its secure connection to the app."
	case ExitPipe:
		return "it could not open its connection to the app (another copy may still be running - restart the PC)."
	case ExitNoClient:
		return "the app did not connect to it in time, or failed its identity check (two Cybervulcan installs? remove the old one)."
	case ExitRunnerPath:
		return "it could not find its own program file."
	case ExitRunnerDLL:
		return "Windows would not load cvwg.dll with admin rights (blocked by Smart App Control or antivirus?)."
	case ExitRunnerExport:
		return "cvwg.dll does not match the app (reinstall Cybervulcan)."
	case 0xC0000135:
		return "a file it needs is missing (reinstall Cybervulcan)."
	case 0xC0000005:
		return "it crashed."
	default:
		return fmt.Sprintf("unexpected exit code 0x%X.", code)
	}
}

// helperLogPath is the elevated helper's log: %ProgramData%\Cybervulcan.
// No keys or addresses beyond the adapter's are ever written to it.
func helperLogPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = filepath.Join(os.TempDir(), "Cybervulcan")
	}
	return filepath.Join(base, "Cybervulcan", "vpn-helper.log")
}
