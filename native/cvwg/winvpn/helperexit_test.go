package winvpn

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestHelperExitReasonKnownCodes(t *testing.T) {
	for _, c := range []uint32{0, ExitBadArgs, ExitNotElevated, ExitSecurity, ExitPipe, ExitNoClient,
		ExitRunnerPath, ExitRunnerDLL, ExitRunnerExport, 0xC0000135, 0xC0000005} {
		r := HelperExitReason(c)
		if r == "" || strings.Contains(r, "unexpected") {
			t.Errorf("code %d: no plain reason (%q)", c, r)
		}
	}
	if !strings.Contains(HelperExitReason(77), "0x4D") {
		t.Error("unknown code should show its value")
	}
	if !strings.Contains(HelperExitReason(ExitRunnerDLL), "cvwg.dll") {
		t.Error("DLL load failure should name cvwg.dll")
	}
}

// v2.1.22: the client must ask for exactly what the pipe grants, or
// Windows refuses every open and the helper "does not answer".
func TestPipeSDDLGrantsClientAccess(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	s, err := PipeSDDL(sid)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("(A;;0x%X;;;%s)", PipeClientAccess, sid)
	if !strings.Contains(s, want) {
		t.Fatalf("SDDL %q does not grant the client access %s", s, want)
	}
	// The elevated helper (Administrators) must be able to add pipe
	// instances for each Accept (v2.1.23).
	if !strings.Contains(s, "(A;;GA;;;BA)") {
		t.Error("Administrators need full access to create pipe instances")
	}
	// No FILE_CREATE_PIPE_INSTANCE (0x4) for the user.
	if PipeClientAccess&0x4 != 0 {
		t.Error("client access must not include FILE_CREATE_PIPE_INSTANCE")
	}
	// Read, write and the reads the dialer needs (owner check, pipe info).
	for _, bit := range []uint32{0x1, 0x2, 0x80, 0x20000, 0x100000} {
		if PipeClientAccess&bit == 0 {
			t.Errorf("client access lacks 0x%X", bit)
		}
	}
}

func TestFriendlyErrorKeepsHelperDetail(t *testing.T) {
	e := errors.New("the admin helper did not answer (open \\\\.\\pipe\\x: Access is denied.)")
	if got := FriendlyError(e); got != e.Error() {
		t.Errorf("helper detail was replaced: %q", got)
	}
}
