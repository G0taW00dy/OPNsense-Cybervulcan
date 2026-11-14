// Command cvwg is built as a C shared library (libcvwg.so on Android,
// cvwg.dll on Windows) and called from Dart through dart:ffi.
//
// C API (all strings are UTF-8, NUL-terminated; every returned string must
// be released with cvwg_free):
//
//	char* cvwg_version(void);
//	char* cvwg_up(const char* configJson);   // {"port":N} or {"error":"..."}
//	char* cvwg_status(void);                 // tunnel.Status as JSON, {"up":false} when down
//	void  cvwg_down(void);
//	void  cvwg_free(char* p);
//
// Only one tunnel exists per process; cvwg_up replaces a running one.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"sync"
	"unsafe"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/tunnel"
)

// Version is reported to the app (and shown in its diagnostics).
const Version = "cvwg 1.1.0"

var (
	mu      sync.Mutex
	current *tunnel.Tunnel
)

func jsonCString(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"error":"internal: json"}`)
	}
	return C.CString(string(b))
}

//export cvwg_version
func cvwg_version() *C.char { return C.CString(Version) }

//export cvwg_up
func cvwg_up(cfgJSON *C.char) *C.char {
	var cfg tunnel.Config
	if err := json.Unmarshal([]byte(C.GoString(cfgJSON)), &cfg); err != nil {
		return jsonCString(map[string]string{"error": "bad config: " + err.Error()})
	}
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		current.Close()
		current = nil
	}
	t, err := tunnel.Start(cfg)
	if err != nil {
		return jsonCString(map[string]string{"error": err.Error()})
	}
	current = t
	return jsonCString(map[string]int{"port": t.Port()})
}

//export cvwg_status
func cvwg_status() *C.char {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return jsonCString(tunnel.Status{Up: false})
	}
	return jsonCString(current.Status())
}

//export cvwg_down
func cvwg_down() {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		current.Close()
		current = nil
	}
}

//export cvwg_free
func cvwg_free(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
