//go:build windows

package winvpn

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// v2.2.1: DNS lock for "everything" mode. Windows asks the DNS servers of
// every network adapter at once ("smart multi-homed name resolution"), so a
// low adapter metric alone still let lookups go out the Wi-Fi's own DNS. A
// Name Resolution Policy Table rule for the whole namespace (".") makes the
// DNS client send every query to the adapter's resolver only. The rule lives
// under the DNS client's own (non-GPO) policy key and is removed when the
// mode stops, and by the next helper start after a crash (cleanupStale).
//
// The tunnel endpoint is resolved by the tray app before the rule is set,
// and every reconnect stops the session first, so the rule never blocks the
// lookup of the endpoint itself.

const (
	nrptBase = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// Fixed name: one rule, found again after a crash.
	nrptRuleKey = nrptBase + `\{C7B0E1A4-3D55-4F2B-9A61-CB5E0D1F2A77}`
)

// REG_OPTION_VOLATILE: the key is kept in memory only (gone after a reboot).
const regOptionVolatile = 0x1

var (
	procRegCreateKeyExW       = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegCreateKeyExW")
	dnsapi                    = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = dnsapi.NewProc("DnsFlushResolverCache")
)

// setDNSLock points all name lookups at servers (the adapter's resolver).
func setDNSLock(servers []netip.Addr) error {
	if len(servers) == 0 {
		return nil
	}
	k, err := createVolatileRuleKey()
	if err != nil {
		return err
	}
	defer k.Close()
	list := ""
	for i, s := range servers {
		if i > 0 {
			list += ";"
		}
		list += s.String()
	}
	if err := k.SetStringsValue("Name", []string{"."}); err != nil {
		return err
	}
	// 0x8 = "use these DNS servers" (generic DNS server rule).
	if err := k.SetDWordValue("ConfigOptions", 0x8); err != nil {
		return err
	}
	if err := k.SetStringValue("GenericDNSServers", list); err != nil {
		return err
	}
	if err := k.SetStringValue("IPSECCARestriction", ""); err != nil {
		return err
	}
	if err := k.SetDWordValue("Version", 2); err != nil {
		return err
	}
	applyDNSPolicy()
	return nil
}

// createVolatileRuleKey creates the rule key as a volatile key (v2.2.5,
// audit M3): Windows discards it at the next boot, so a power cut or crash in
// "everything" mode can no longer leave all DNS pointed at a dead tunnel
// across reboots. The parent stays a normal key (it is shared with other
// policies); an older non-volatile rule key is replaced.
func createVolatileRuleKey() (registry.Key, error) {
	parent, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptBase, registry.CREATE_SUB_KEY)
	if err != nil {
		return 0, err
	}
	defer parent.Close()
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, nrptRuleKey)
	name, err := windows.UTF16PtrFromString(nrptRuleKey[len(nrptBase)+1:])
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	var disp uint32
	r, _, _ := procRegCreateKeyExW.Call(uintptr(parent), uintptr(unsafe.Pointer(name)), 0, 0,
		regOptionVolatile, uintptr(registry.SET_VALUE), 0,
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disp)))
	if r != 0 {
		return 0, windows.Errno(r)
	}
	return registry.Key(h), nil
}

// DNSLockPresent reports whether the "everything" DNS rule exists. Readable
// without admin rights, so the tray app can offer a repair when no helper
// is running (v2.2.5).
func DNSLockPresent() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptRuleKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	k.Close()
	return true
}

// clearDNSLock removes the rule (no error when it is not there).
func clearDNSLock() {
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptRuleKey); err == nil {
		applyDNSPolicy()
	}
}

// applyDNSPolicy tells the DNS client to re-read its policy and drops cached
// answers that came from other servers.
func applyDNSPolicy() {
	if m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT); err == nil {
		name, _ := windows.UTF16PtrFromString("Dnscache")
		if s, err := windows.OpenService(m, name, windows.SERVICE_PAUSE_CONTINUE); err == nil {
			var st windows.SERVICE_STATUS
			_ = windows.ControlService(s, windows.SERVICE_CONTROL_PARAMCHANGE, &st)
			windows.CloseServiceHandle(s)
		}
		windows.CloseServiceHandle(m)
	}
	_, _, _ = procDnsFlushResolverCache.Call()
}
