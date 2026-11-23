//go:build windows

package winvpn

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// helperLogMax caps the log; past it the file starts over.
const helperLogMax = 64 * 1024

// helperLogSDDL protects the log folder and file (v2.2.5, audit H2): owned
// by Administrators, full control for SYSTEM and Administrators, read-only
// for users (the app shows the log), inherited ACEs blocked. Before this a
// user could pre-create the folder or plant a link in it and make the
// elevated helper create, append to or truncate a file of their choosing.
const helperLogSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)"

// helperLogf appends one line to the helper's log (best effort). Only
// states and error texts - never keys, tokens or peer addresses. Nothing is
// written unless the folder and file pass the ownership and link checks.
func helperLogf(format string, args ...any) {
	line := fmt.Sprintf("%s pid %d: %s\n", time.Now().Format("2006-01-02 15:04:05"), os.Getpid(), fmt.Sprintf(format, args...))
	_ = appendHelperLog(line)
}

// knownHelperLogPath is where the log lives, from the Known Folder API
// (not the user-controllable %ProgramData% variable). Read-only use.
func knownHelperLogPath() string {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return helperLogPath()
	}
	return filepath.Join(base, "Cybervulcan", "vpn-helper.log")
}

// secureHelperLogPath is the log path from the Known Folder API (not the
// user-controllable %ProgramData% variable), with its folder checked and
// locked down.
func secureHelperLogPath() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "Cybervulcan")
	sd, err := windows.SecurityDescriptorFromString(helperLogSDDL)
	if err != nil {
		return "", err
	}
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", err
	}
	attrs, err := windows.GetFileAttributes(dirPtr)
	switch {
	case err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND:
		sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
		if err := windows.CreateDirectory(dirPtr, sa); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	default:
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return "", fmt.Errorf("log folder is a link or not a folder - not logging")
		}
		cur, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return "", err
		}
		owner, _, err := cur.Owner()
		if err != nil || !trustedOwner(owner) {
			return "", fmt.Errorf("log folder is not owned by Administrators or SYSTEM - not logging")
		}
		// Re-apply the protected DACL (older versions inherited ProgramData's,
		// which lets users create files in the folder).
		dacl, _, err := sd.DACL()
		if err != nil {
			return "", err
		}
		if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, "vpn-helper.log"), nil
}

func trustedOwner(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid))
}

func appendHelperLog(line string) error {
	p, err := secureHelperLogPath()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(helperLogSDDL)
	if err != nil {
		return err
	}
	pPtr, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	// FILE_FLAG_OPEN_REPARSE_POINT: a planted link is opened as itself, never
	// followed; it is then refused below.
	h, err := windows.CreateFile(pPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.READ_CONTROL,
		windows.FILE_SHARE_READ, sa, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return fmt.Errorf("log file is a link - not logging")
	}
	// A file left by an older version (or pre-created by a user) gets the
	// protected owner and DACL before anything is written.
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return err
	}
	size := int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow)
	if size > helperLogMax {
		if _, err := windows.Seek(h, 0, 0); err != nil {
			return err
		}
		if err := windows.SetEndOfFile(h); err != nil {
			return err
		}
	}
	if _, err := windows.Seek(h, 0, 2); err != nil {
		return err
	}
	var n uint32
	return windows.WriteFile(h, []byte(line), &n, nil)
}
