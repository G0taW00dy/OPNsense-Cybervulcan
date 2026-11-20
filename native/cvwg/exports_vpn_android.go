//go:build android

package main

// System-VPN exports for Android. The VpnService (Kotlin,
// CybervulcanVpnService) builds the interface, detaches its fd and hands it
// to Go; from then on Go owns the fd and closes it on stop.
//
// The same functions are reachable two ways, because the VPN must keep
// working when the Flutter engine is gone (app swiped away, VPN restarted
// by Android):
//
//	C (dart:ffi):  char* cvvpn_start(int fd, const char* configJson); // {"up":true} | {"error":"..."}
//	               char* cvvpn_status(void);                          // vpnStatus JSON
//	               void  cvvpn_stop(void);
//	JNI (Kotlin):  au.cybervulcan.opnsense.CvNative.vpnStart(fd: Int, json: String): String
//	               au.cybervulcan.opnsense.CvNative.vpnStatus(): String
//	               au.cybervulcan.opnsense.CvNative.vpnStop()
//
// Strings returned by the C functions must be released with cvwg_free.
// Kotlin loads this library with System.loadLibrary("cvwg"); dart:ffi opens
// the same libcvwg.so, so there is still exactly one Go runtime.

/*
#include <stdlib.h>
#include <jni.h>

// jni_android.c
const char* cv_jstring_chars(JNIEnv* env, jstring s);
void cv_jstring_release(JNIEnv* env, jstring s, const char* c);
jstring cv_new_jstring(JNIEnv* env, const char* c);
*/
import "C"

import (
	"fmt"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun"
)

func vpnStartFD(fd int, cfgJSON string) string {
	if fd < 0 {
		return jsonString(map[string]string{"error": "no VPN interface (fd)"})
	}
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return jsonString(map[string]string{"error": fmt.Sprintf("VPN interface: %v", err)})
	}
	return vpnStart(dev, cfgJSON)
}

//export cvvpn_start
func cvvpn_start(fd C.int, cfgJSON *C.char) *C.char {
	return C.CString(vpnStartFD(int(fd), C.GoString(cfgJSON)))
}

//export cvvpn_status
func cvvpn_status() *C.char { return C.CString(vpnStatusJSON()) }

//export cvvpn_stop
func cvvpn_stop() { vpnStop() }

func goJString(env *C.JNIEnv, s C.jstring) string {
	if s == 0 {
		return ""
	}
	c := C.cv_jstring_chars(env, s)
	if c == nil {
		return ""
	}
	defer C.cv_jstring_release(env, s, c)
	return C.GoString(c)
}

func newJString(env *C.JNIEnv, s string) C.jstring {
	c := C.CString(s)
	defer C.free(unsafe.Pointer(c))
	return C.cv_new_jstring(env, c)
}

//export Java_au_cybervulcan_opnsense_CvNative_vpnStart
func Java_au_cybervulcan_opnsense_CvNative_vpnStart(env *C.JNIEnv, obj C.jobject, fd C.jint, cfgJSON C.jstring) C.jstring {
	return newJString(env, vpnStartFD(int(fd), goJString(env, cfgJSON)))
}

//export Java_au_cybervulcan_opnsense_CvNative_vpnStatus
func Java_au_cybervulcan_opnsense_CvNative_vpnStatus(env *C.JNIEnv, obj C.jobject) C.jstring {
	return newJString(env, vpnStatusJSON())
}

//export Java_au_cybervulcan_opnsense_CvNative_vpnStop
func Java_au_cybervulcan_opnsense_CvNative_vpnStop(env *C.JNIEnv, obj C.jobject) { vpnStop() }
