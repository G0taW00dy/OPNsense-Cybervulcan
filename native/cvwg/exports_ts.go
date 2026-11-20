package main

// Built-in Tailscale (package ts). C API, same string rules as main.go
// (UTF-8, NUL-terminated, release every returned string with cvwg_free):
//
//	char* cvts_start(const char* configJson);  // ts.Status JSON (state, authUrl, port, ...) or {"error":"..."}
//	char* cvts_status(void);                   // ts.Status JSON; {"up":false,"state":"stopped"} when down
//	void  cvts_down(void);                     // stop; the login is kept
//	char* cvts_logout(const char* configJson); // sign out + delete state; {"ok":true} or {"error":"..."}
//
// configJson for cvts_start: {"stateDir","hostname","target","token","controlURL"?,"waitMs"?}
// (see ts.Config). cvts_logout needs only {"stateDir"} (may be NULL while running).

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/ts"
)

var tsService ts.Service

//export cvts_start
func cvts_start(cfgJSON *C.char) *C.char {
	cfg := C.GoString(cfgJSON)
	captureCrashes(cfg)
	return C.CString(tsService.Start(cfg))
}

var crashOnce sync.Once

// captureCrashes sends a fatal Go crash (panic, fatal error) to
// <stateDir>/../native-crash.txt as well as stderr, so the app can show it
// in "Copy diagnostics" on the next start (v2.1.3: on Android the app was
// closing ~2 s after start with nothing in the Dart error log).
func captureCrashes(cfgJSON string) {
	var c struct {
		StateDir string `json:"stateDir"`
	}
	if json.Unmarshal([]byte(cfgJSON), &c) != nil || c.StateDir == "" {
		return
	}
	crashOnce.Do(func() {
		dir := filepath.Dir(filepath.Clean(c.StateDir))
		_ = os.MkdirAll(dir, 0o700)
		f, err := os.OpenFile(filepath.Join(dir, "native-crash.txt"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			_ = debug.SetCrashOutput(f, debug.CrashOptions{})
		}
	})
}

//export cvts_status
func cvts_status() *C.char { return C.CString(tsService.Status()) }

//export cvts_down
func cvts_down() { tsService.Down() }

//export cvts_logout
func cvts_logout(cfgJSON *C.char) *C.char {
	arg := ""
	if cfgJSON != nil {
		arg = C.GoString(cfgJSON)
	}
	return C.CString(tsService.Logout(arg))
}
