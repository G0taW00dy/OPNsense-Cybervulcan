//go:build windows

package main

// System-VPN exports for Windows ("home link": remote modes "home" and
// "everything"). The Cybervulcan Wintun adapter is created by the elevated
// helper (package winvpn, UAC prompt); its packets come back to this process
// over a pipe and run through the same VPN core and remote-access transport
// as on Android (vpn_glue.go: vpnStart / vpnStatusJSON / vpnStop).
// Strings follow the cvwg_* rules in main.go (UTF-8, release with cvwg_free).
//
//	char* cvvpn_start(const char* json); // {"ok":true} | {"error":"..."}; async, poll cvvpn_status
//	char* cvvpn_status(void);            // {"helper":winvpn.Status,"vpn":vpnStatus}
//	void  cvvpn_stop(void);
//	int   cvvpn_helper_main(void);       // the elevated helper (Cybervulcan.exe --vpn-helper ...)
//
// cvvpn_start JSON: {"helper": winvpn.StartRequest, "vpn": vpnStartConfig}.

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/winvpn"
)

type winVpnStart struct {
	Helper json.RawMessage `json:"helper"`
	VPN    json.RawMessage `json:"vpn"`
}

var (
	vpnClient winvpn.Client

	winVpnMu  sync.Mutex
	winVpnCfg string // vpnStartConfig JSON for the next packet pipe
)

func init() {
	vpnClient.OnPackets = func(conn net.Conn, mtu int) error {
		winVpnMu.Lock()
		cfg := winVpnCfg
		winVpnMu.Unlock()
		// vpnStart owns (and on failure closes) the device.
		var reply map[string]any
		_ = json.Unmarshal([]byte(vpnStart(winvpn.NewPipeTun(conn, mtu), cfg)), &reply)
		if e, ok := reply["error"].(string); ok && e != "" {
			return errors.New(e)
		}
		return nil
	}
	vpnClient.OnStop = vpnStop
}

func winVpnParse(s string) (winvpn.StartRequest, string, error) {
	var w winVpnStart
	if err := json.Unmarshal([]byte(s), &w); err != nil || len(w.Helper) == 0 || len(w.VPN) == 0 {
		return winvpn.StartRequest{}, "", errors.New("bad home link settings")
	}
	r, err := winvpn.ParseStartJSON(w.Helper)
	if err != nil {
		return r, "", err
	}
	var vc vpnStartConfig
	if err := json.Unmarshal(w.VPN, &vc); err != nil {
		return r, "", errors.New("bad home link settings")
	}
	if _, err := vc.Config.Options(); err != nil {
		return r, "", err
	}
	eff := func(m int) int {
		if m == 0 {
			return 1280 // both sides' default
		}
		return m
	}
	if eff(vc.MTU) != eff(r.MTU) {
		return r, "", errors.New("adapter and VPN MTU differ")
	}
	return r, string(w.VPN), nil
}

//export cvvpn_start
func cvvpn_start(reqJSON *C.char) *C.char {
	r, cfg, err := winVpnParse(C.GoString(reqJSON))
	if err == nil {
		winVpnMu.Lock()
		winVpnCfg = cfg
		winVpnMu.Unlock()
		err = vpnClient.Start(r)
	}
	if err != nil {
		return jsonCString(map[string]string{"error": err.Error()})
	}
	return jsonCString(map[string]bool{"ok": true})
}

//export cvvpn_status
func cvvpn_status() *C.char {
	h := vpnClient.Status()
	return jsonCString(map[string]any{"helper": h, "vpn": json.RawMessage(vpnStatusJSON())})
}

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
