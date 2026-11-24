// Package minisign verifies minisign signatures (https://jedisct1.github.io/minisign/).
//
// The app uses it to check every downloaded update against the publisher's
// public key compiled into the app, before the update is installed. Only
// verification is implemented; signing happens in the release pipeline.
package minisign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// PublicKey is a minisign Ed25519 public key.
type PublicKey struct {
	KeyID [8]byte
	Key   ed25519.PublicKey
}

// ParsePublicKey reads the base64 key ("RWQ...") or a whole .pub file.
func ParsePublicKey(s string) (PublicKey, error) {
	var pk PublicKey
	line := lastNonCommentLine(s)
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(raw) != 42 {
		return pk, errors.New("minisign: bad public key")
	}
	if raw[0] != 'E' || raw[1] != 'd' {
		return pk, errors.New("minisign: unsupported public key algorithm")
	}
	copy(pk.KeyID[:], raw[2:10])
	pk.Key = ed25519.PublicKey(append([]byte(nil), raw[10:42]...))
	return pk, nil
}

// Signature is a parsed .minisig file.
type Signature struct {
	Prehashed       bool // "ED": BLAKE2b-512 of the file is signed
	KeyID           [8]byte
	Sig             []byte
	TrustedComment  string
	GlobalSignature []byte
}

// MaxSignatureSize bounds the .minisig text accepted.
const MaxSignatureSize = 4096

// ParseSignature reads the text of a .minisig file.
func ParseSignature(text string) (Signature, error) {
	var s Signature
	if len(text) > MaxSignatureSize {
		return s, errors.New("minisign: signature file too large")
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "untrusted comment:") {
		return s, errors.New("minisign: bad signature file")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(raw) != 74 {
		return s, errors.New("minisign: bad signature")
	}
	switch string(raw[:2]) {
	case "Ed":
	case "ED":
		s.Prehashed = true
	default:
		return s, errors.New("minisign: unsupported signature algorithm")
	}
	copy(s.KeyID[:], raw[2:10])
	s.Sig = append([]byte(nil), raw[10:74]...)
	const tc = "trusted comment: "
	if !strings.HasPrefix(lines[2], tc) {
		return s, errors.New("minisign: missing trusted comment")
	}
	s.TrustedComment = strings.TrimSuffix(lines[2][len(tc):], "\r")
	g, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil || len(g) != ed25519.SignatureSize {
		return s, errors.New("minisign: bad global signature")
	}
	s.GlobalSignature = g
	return s, nil
}

// Verify checks data against sig with pk. It returns the trusted comment on
// success. Both the file signature and the trusted-comment (global)
// signature must be valid, and the key IDs must match.
func Verify(pk PublicKey, sig Signature, data io.Reader) (string, error) {
	if !bytes.Equal(pk.KeyID[:], sig.KeyID[:]) {
		return "", errors.New("minisign: signed with a different key")
	}
	var msg []byte
	if sig.Prehashed {
		h, _ := blake2b.New512(nil)
		if _, err := io.Copy(h, data); err != nil {
			return "", fmt.Errorf("minisign: read: %w", err)
		}
		msg = h.Sum(nil)
	} else {
		b, err := io.ReadAll(data)
		if err != nil {
			return "", fmt.Errorf("minisign: read: %w", err)
		}
		msg = b
	}
	if !ed25519.Verify(pk.Key, msg, sig.Sig) {
		return "", errors.New("minisign: signature does not match the file")
	}
	global := append(append([]byte(nil), sig.Sig...), []byte(sig.TrustedComment)...)
	if !ed25519.Verify(pk.Key, global, sig.GlobalSignature) {
		return "", errors.New("minisign: trusted comment signature is invalid")
	}
	return sig.TrustedComment, nil
}

func lastNonCommentLine(s string) string {
	out := ""
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			out = l
		}
	}
	return out
}
