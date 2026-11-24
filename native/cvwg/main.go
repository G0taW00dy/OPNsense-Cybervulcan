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
//	char* cvwg_verify_file(const char* pubKey, const char* path, const char* minisig);
//	                                         // "" when valid, else the reason
//
// Only one tunnel exists per process; cvwg_up replaces a running one.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"os"
	"sync"
	"unsafe"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/internal/minisign"
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

// cvwg_verify_file checks a downloaded update against the publisher's
// minisign signature before it is installed (v2.2.5). Returns "" when the
// signature is valid for pubKey, otherwise the reason.
//
//export cvwg_verify_file
func cvwg_verify_file(pubKey, path, sigText *C.char) *C.char {
	return C.CString(verifyFile(C.GoString(pubKey), C.GoString(path), C.GoString(sigText)))
}

func verifyFile(pubKey, path, sigText string) string {
	pk, err := minisign.ParsePublicKey(pubKey)
	if err != nil {
		return err.Error()
	}
	sig, err := minisign.ParseSignature(sigText)
	if err != nil {
		return err.Error()
	}
	f, err := os.Open(path)
	if err != nil {
		return "open: " + err.Error()
	}
	defer f.Close()
	if _, err := minisign.Verify(pk, sig, f); err != nil {
		return err.Error()
	}
	return ""
}

//export cvwg_free
func cvwg_free(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
