//go:build windows

package main

// Windows "home link": remote access modes "home" and "everything" through
// a Wintun adapter (package winvpn). Strings follow the cvwg_* rules in
// main.go (UTF-8, release with cvwg_free).
//
//	char* cvvpn_start(const char* json); // {"ok":true} or {"error":"..."}; async, poll cvvpn_status
//	char* cvvpn_status(void);            // winvpn.Status as JSON
//	void  cvvpn_stop(void);
//	int   cvvpn_helper_main(void);       // the elevated helper (Cybervulcan.exe --vpn-helper ...)

/*
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/winvpn"
)

var vpnClient winvpn.Client

//export cvvpn_start
func cvvpn_start(reqJSON *C.char) *C.char {
	r, err := winvpn.ParseStartJSON([]byte(C.GoString(reqJSON)))
	if err == nil {
		err = vpnClient.Start(r)
	}
	if err != nil {
		return jsonCString(map[string]string{"error": err.Error()})
	}
	return jsonCString(map[string]bool{"ok": true})
}

//export cvvpn_status
func cvvpn_status() *C.char { return jsonCString(vpnClient.Status()) }

//export cvvpn_stop
func cvvpn_stop() { vpnClient.Stop() }

// cvvpn_helper_main is called by the app's runner (windows/runner/main.cpp)
// instead of starting Flutter when the exe was launched with --vpn-helper.
// It reads the command line itself, so nothing is passed through C.
//
//export cvvpn_helper_main
func cvvpn_helper_main() C.int {
	var argc int32
	argv, err := windows.CommandLineToArgv(windows.GetCommandLine(), &argc)
	if err != nil {
		return 2
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(argv)))
	var args []string
	for i := 1; i < int(argc); i++ {
		args = append(args, windows.UTF16PtrToString(&argv[i][0]))
	}
	return C.int(winvpn.RunHelper(args))
}
