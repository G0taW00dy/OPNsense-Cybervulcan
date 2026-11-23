//go:build windows

package winvpn

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// helperLogMax caps the log; past it the file starts over.
const helperLogMax = 64 * 1024

// helperLogf appends one line to the helper's log (best effort). Only
// states and error texts - never keys, tokens or peer addresses.
func helperLogf(format string, args ...any) {
	p := helperLogPath()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(p); err == nil && fi.Size() > helperLogMax {
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	f, err := os.OpenFile(p, flags, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s pid %d: %s\n", time.Now().Format("2006-01-02 15:04:05"), os.Getpid(), fmt.Sprintf(format, args...))
}
