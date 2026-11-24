//go:build !windows

package ts

import "tailscale.com/ipn"

// platformStore: nil = tsnet's own file store in the app's private folder
// (Android app storage is not readable by other apps).
func platformStore(dir string) (ipn.StateStore, error) { return nil, nil }
