//go:build windows

package ts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/ipn"
)

// v2.2.5 (audit L8): on Windows the Tailscale node key and login state are
// kept encrypted with DPAPI (bound to the Windows user) instead of a plain
// JSON file under %APPDATA%. Android keeps the state in the app's private
// storage, which other apps can't read.

const (
	encryptedStateFile = "tailscaled.state.dpapi"
	plainStateFile     = "tailscaled.state" // tsnet's default; migrated once
)

type dpapiStore struct {
	path  string
	mu    sync.Mutex
	cache map[ipn.StateKey][]byte
}

// platformStore returns the encrypted state store for dir, moving a plain
// state file left by an older version into it.
func platformStore(dir string) (ipn.StateStore, error) {
	s := &dpapiStore{path: filepath.Join(dir, encryptedStateFile), cache: map[ipn.StateKey][]byte{}}
	if enc, err := os.ReadFile(s.path); err == nil {
		plain, err := dpapiDecrypt(enc)
		if err != nil {
			return nil, errors.New("cannot read the Tailscale state (encrypted for another Windows user?): " + err.Error())
		}
		if err := json.Unmarshal(plain, &s.cache); err != nil {
			return nil, err
		}
		return s, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	old := filepath.Join(dir, plainStateFile)
	if b, err := os.ReadFile(old); err == nil {
		if json.Unmarshal(b, &s.cache) == nil {
			if err := s.saveLocked(); err != nil {
				return nil, err
			}
			_ = os.Remove(old)
		}
	}
	return s, nil
}

func (s *dpapiStore) ReadState(id ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.cache[id]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return append([]byte(nil), b...), nil
}

func (s *dpapiStore) WriteState(id ipn.StateKey, bs []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bs == nil {
		delete(s.cache, id)
	} else {
		s.cache[id] = append([]byte(nil), bs...)
	}
	return s.saveLocked()
}

func (s *dpapiStore) saveLocked() error {
	plain, err := json.Marshal(s.cache)
	if err != nil {
		return err
	}
	enc, err := dpapiEncrypt(plain)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, enc, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

var dpapiEntropy = []byte("Cybervulcan Tailscale state v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func dpapiEncrypt(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(plain), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func dpapiDecrypt(enc []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(enc), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}
