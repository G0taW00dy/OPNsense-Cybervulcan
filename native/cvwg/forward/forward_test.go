package forward

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func newToken(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, TokenSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// echoDial returns a DialFunc that hands out one end of a pipe whose other
// end echoes everything back, and counts dials.
func echoDial(n *atomic.Int32) DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		n.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_, _ = io.Copy(b, b)
		}()
		return a, nil
	}
}

func TestParseToken(t *testing.T) {
	tok := newToken(t)
	got, err := ParseToken(base64.StdEncoding.EncodeToString(tok))
	if err != nil || !bytes.Equal(got, tok) {
		t.Fatalf("valid token rejected: %v", err)
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(tok[:31])} {
		if _, err := ParseToken(bad); err == nil {
			t.Errorf("ParseToken(%q) accepted", bad)
		}
	}
}

func TestForwardsWithRightToken(t *testing.T) {
	tok := newToken(t)
	var dials atomic.Int32
	f, err := Start(tok, echoDial(&dials), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(f.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg := []byte("hello router")
	if _, err := c.Write(append(append([]byte(nil), tok...), msg...)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo = %q", got)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d", dials.Load())
	}
}

func TestRejectsWrongOrShortToken(t *testing.T) {
	old := TokenTimeout
	TokenTimeout = 300 * time.Millisecond
	defer func() { TokenTimeout = old }()

	tok := newToken(t)
	var dials atomic.Int32
	f, err := Start(tok, echoDial(&dials), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	wrong := newToken(t)
	for name, send := range map[string][]byte{"wrong": wrong, "short": tok[:10], "none": nil} {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(f.Port())))
		if err != nil {
			t.Fatal(err)
		}
		if len(send) > 0 {
			_, _ = c.Write(send)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, err := c.Read(make([]byte, 1)); err == nil {
			t.Errorf("%s token: read %d bytes, want closed connection", name, n)
		}
		c.Close()
	}
	if dials.Load() != 0 {
		t.Fatalf("forwarder dialled %d times without a valid token", dials.Load())
	}
}

func TestDialErrorReported(t *testing.T) {
	tok := newToken(t)
	got := make(chan error, 1)
	f, err := Start(tok, func(context.Context) (net.Conn, error) { return nil, errors.New("no route") },
		func(err error) { got <- err })
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(f.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(tok)
	select {
	case err := <-got:
		if err.Error() != "no route" {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial error not reported")
	}
}

func TestStartValidates(t *testing.T) {
	if _, err := Start(make([]byte, 5), echoDial(new(atomic.Int32)), nil); err == nil {
		t.Error("short token accepted")
	}
	if _, err := Start(newToken(t), nil, nil); err == nil {
		t.Error("nil dial accepted")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	f, err := Start(newToken(t), echoDial(new(atomic.Int32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	f.Close()
	if _, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(f.Port())), time.Second); err == nil {
		t.Error("listener still open after Close")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
