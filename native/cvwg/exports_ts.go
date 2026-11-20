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

import "github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/ts"

var tsService ts.Service

//export cvts_start
func cvts_start(cfgJSON *C.char) *C.char {
	return C.CString(tsService.Start(C.GoString(cfgJSON)))
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
