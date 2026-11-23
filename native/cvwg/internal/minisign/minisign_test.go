package minisign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Vectors made with an independent implementation (Python "cryptography" +
// hashlib.blake2b) from a fixed test key - not the release key.
const (
	testPub  = "RWQBAgMEBQYHCAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
	testData = "Cybervulcan test update\n"
	sigPre   = "untrusted comment: signature from minisign secret key\nRUQBAgMEBQYHCJFVsjj2wQSlXYlcFWba4C0hLlVutbN6HiZ1wOpGd3esF8xMzA/EjT8cPw+6Xms6lQrCwrQIcOFMo0QfXQvL3gw=\ntrusted comment: timestamp:1795470000\tfile:test.bin\nZdJ9rLr4feYlwoJ88gubl5TUCHYKCDmTFVB7uBQ/9ukaINnGKRfXMHCoD7i4pu9+nut/fweKS7MOsIlQbq6lDw==\n"
	sigLeg   = "untrusted comment: signature from minisign secret key\nRWQBAgMEBQYHCCsqNhm7umoBJmQ8O8trHgl/5vEw1p4czys9Cju6gsqCRZxcMgml0ysoc+cr+UViMI2gDrD/yimAsrTv3qUvww4=\ntrusted comment: timestamp:1795470000\tfile:test.bin\nld5XM9ySZUXXfN2d8IgHQrJpVOaf+XwnOpPPIK7901TOmv9qSsOWNcvIWshqb+AB5uNHueiVvYJLFgMtUNcRCA==\n"
	// The real release public key (public by design).
	releasePub = "RWQYKjXHIYJR9eM++raYyQ7jSsxbxcslD0OKlgL2Y7VTxzuGZOOtThsG"
)

func mustPub(t *testing.T, s string) PublicKey {
	t.Helper()
	pk, err := ParsePublicKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestVerifyGood(t *testing.T) {
	pk := mustPub(t, testPub)
	for name, text := range map[string]string{"prehashed": sigPre, "legacy": sigLeg} {
		sig, err := ParseSignature(text)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		tc, err := Verify(pk, sig, strings.NewReader(testData))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tc != "timestamp:1795470000\tfile:test.bin" {
			t.Fatalf("%s: trusted comment %q", name, tc)
		}
	}
	// CRLF line endings (a .minisig saved on Windows) still verify.
	sig, err := ParseSignature(strings.ReplaceAll(sigPre, "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pk, sig, strings.NewReader(testData)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pk := mustPub(t, testPub)
	sig, _ := ParseSignature(sigPre)

	if _, err := Verify(pk, sig, strings.NewReader(testData+"x")); err == nil {
		t.Fatal("changed file accepted")
	}
	// Edited trusted comment: the global signature must catch it.
	bad := sig
	bad.TrustedComment = "timestamp:1795470000\tfile:evil.bin"
	if _, err := Verify(pk, bad, strings.NewReader(testData)); err == nil {
		t.Fatal("edited trusted comment accepted")
	}
	// A different key (the release key) must not verify a test signature.
	if _, err := Verify(mustPub(t, releasePub), sig, strings.NewReader(testData)); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, s := range []string{"", "untrusted comment: x\nAAAA\ntrusted comment: y\nAAAA\n", strings.Repeat("a", MaxSignatureSize+1)} {
		if _, err := ParseSignature(s); err == nil {
			t.Fatalf("garbage signature parsed: %q", s[:min(len(s), 20)])
		}
	}
	if _, err := ParsePublicKey("not a key"); err == nil {
		t.Fatal("garbage key parsed")
	}
}

func TestReleaseKeyParses(t *testing.T) {
	pk := mustPub(t, "untrusted comment: minisign public key\n"+releasePub+"\n")
	if len(pk.Key) != 32 {
		t.Fatal("bad key length")
	}
}

// TestRealMinisign checks files made by the real minisign tool in CI
// (MINISIGN_REAL_DIR holds test.pub, test.bin and test.bin.minisig).
func TestRealMinisign(t *testing.T) {
	dir := os.Getenv("MINISIGN_REAL_DIR")
	if dir == "" {
		t.Skip("MINISIGN_REAL_DIR not set")
	}
	pub, err := os.ReadFile(filepath.Join(dir, "test.pub"))
	if err != nil {
		t.Fatal(err)
	}
	sigText, err := os.ReadFile(filepath.Join(dir, "test.bin.minisig"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := ParseSignature(string(sigText))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "test.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := Verify(mustPub(t, string(pub)), sig, f); err != nil {
		t.Fatal(err)
	}
}
