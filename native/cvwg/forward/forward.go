// Package forward is the loopback TCP forwarder shared by the remote-access
// engines (package tunnel = WireGuard, package ts = Tailscale):
//
//	app --TCP--> 127.0.0.1:<random port> --engine--> target (router:443)
//
// Every accepted connection must start with the 32-byte access token, so
// other apps or processes on the same device cannot use the forwarder. The
// token is consumed; everything after it (the TLS handshake with the router,
// then HTTP) is relayed unchanged, so the app still checks the router's
// certificate end to end.
package forward

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// TokenSize is the length of the access token each forwarded connection
// must send first.
const TokenSize = 32

// Timeouts (variables so tests can shorten them).
var (
	// TokenTimeout is how long a new connection has to send the token.
	TokenTimeout = 5 * time.Second
	// DialTimeout limits each dial through the engine.
	DialTimeout = 10 * time.Second
)

// DialFunc opens the onward connection to the (fixed) target.
type DialFunc func(ctx context.Context) (net.Conn, error)

// ParseToken decodes a base64 access token and checks its length.
func ParseToken(b64 string) ([]byte, error) {
	token, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(token) != TokenSize {
		return nil, errors.New("access token must be 32 bytes, base64")
	}
	return token, nil
}

// Forwarder accepts loopback connections, checks the token and relays them
// to whatever Dial returns.
type Forwarder struct {
	ln    net.Listener
	token []byte
	dial  DialFunc
	onErr func(error)

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// Start listens on 127.0.0.1 (random port). onErr (optional) receives dial
// errors so the engine can report them in its status.
func Start(token []byte, dial DialFunc, onErr func(error)) (*Forwarder, error) {
	if len(token) != TokenSize {
		return nil, errors.New("access token must be 32 bytes")
	}
	if dial == nil {
		return nil, errors.New("no dial function")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &Forwarder{ln: ln, token: append([]byte(nil), token...), dial: dial, onErr: onErr}
	f.wg.Add(1)
	go f.acceptLoop()
	return f, nil
}

// Port is the loopback port.
func (f *Forwarder) Port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *Forwarder) acceptLoop() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

// CheckToken reads TokenSize bytes from c (within TokenTimeout) and compares
// them in constant time with want.
func CheckToken(c net.Conn, want []byte) bool {
	_ = c.SetReadDeadline(time.Now().Add(TokenTimeout))
	got := make([]byte, TokenSize)
	if _, err := io.ReadFull(c, got); err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false
	}
	_ = c.SetReadDeadline(time.Time{})
	return true
}

type closeWriter interface{ CloseWrite() error }

func (f *Forwarder) handle(c net.Conn) {
	defer c.Close()
	if !CheckToken(c, f.token) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), DialTimeout)
	rc, err := f.dial(ctx)
	cancel()
	if err != nil {
		if f.onErr != nil {
			f.onErr(err)
		}
		return
	}
	defer rc.Close()
	Relay(c, rc)
}

// Relay copies both ways until both directions are done, passing half-closes
// on where the connection type supports them.
func Relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(b, a)
	go pipe(a, b)
	<-done
	<-done
}

// Close stops accepting. Connections already relaying finish on their own.
func (f *Forwarder) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.mu.Unlock()
	_ = f.ln.Close()
	f.wg.Wait()
}
