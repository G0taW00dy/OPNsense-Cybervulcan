package winvpn

import (
	"bufio"
	"errors"
	"net"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// PipeTun is the tray app's view of the Cybervulcan adapter: a tun.Device
// whose packets travel over the helper's packet pipe. The VPN core (package
// vpn) runs on it exactly as on Android's VpnService device.
type PipeTun struct {
	conn net.Conn
	rd   *bufio.Reader
	mtu  int

	wmu    sync.Mutex
	events chan tun.Event
	once   sync.Once
}

// NewPipeTun wraps the packet pipe.
func NewPipeTun(conn net.Conn, mtu int) *PipeTun {
	t := &PipeTun{conn: conn, rd: bufio.NewReaderSize(conn, 64*1024), mtu: mtu, events: make(chan tun.Event, 1)}
	t.events <- tun.EventUp
	return t
}

func (t *PipeTun) File() *os.File           { return nil }
func (t *PipeTun) MTU() (int, error)        { return t.mtu, nil }
func (t *PipeTun) Name() (string, error)    { return AdapterName, nil }
func (t *PipeTun) Events() <-chan tun.Event { return t.events }
func (t *PipeTun) BatchSize() int           { return 1 }

// Read reads one packet.
func (t *PipeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}
	buf := bufs[0][offset:]
	n, err := ReadFrame(t.rd, buf)
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write writes packets.
func (t *PipeTun) Write(bufs [][]byte, offset int) (int, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for i, b := range bufs {
		if err := WriteFrame(t.conn, b[offset:]); err != nil {
			if errors.Is(err, errFrame) {
				continue // oversized: drop like a real interface would
			}
			return i, err
		}
	}
	return len(bufs), nil
}

// Close closes the pipe (the helper then removes the adapter).
func (t *PipeTun) Close() error {
	var err error
	t.once.Do(func() {
		err = t.conn.Close()
		close(t.events)
	})
	return err
}
