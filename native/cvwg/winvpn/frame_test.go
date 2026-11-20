package winvpn

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	pkts := [][]byte{{0x45, 1, 2, 3}, bytes.Repeat([]byte{7}, maxMTU)}
	for _, p := range pkts {
		if err := WriteFrame(&b, p); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, MaxFrame)
	for _, p := range pkts {
		n, err := ReadFrame(&b, buf)
		if err != nil || !bytes.Equal(buf[:n], p) {
			t.Fatalf("got %d %v", n, err)
		}
	}
}

func TestFrameRejects(t *testing.T) {
	if WriteFrame(&bytes.Buffer{}, nil) == nil || WriteFrame(&bytes.Buffer{}, make([]byte, MaxFrame+1)) == nil {
		t.Error("empty / oversized packet written")
	}
	for _, n := range []uint16{0, MaxFrame + 1, 0xffff} {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, n)
		b.Write(make([]byte, int(n)))
		if _, err := ReadFrame(&b, make([]byte, MaxFrame)); err == nil {
			t.Errorf("frame length %d accepted", n)
		}
	}
	// A frame larger than the reader's buffer is refused, not truncated.
	var b bytes.Buffer
	_ = WriteFrame(&b, make([]byte, 100))
	if _, err := ReadFrame(&b, make([]byte, 50)); err == nil {
		t.Error("frame larger than buffer accepted")
	}
}

func TestPipeTun(t *testing.T) {
	a, b := net.Pipe()
	dev := NewPipeTun(a, 1280)
	defer dev.Close()
	if ev := <-dev.Events(); ev != 1 { // tun.EventUp
		t.Errorf("first event %d", ev)
	}
	if n, _ := dev.Name(); n != AdapterName {
		t.Error(n)
	}

	// Helper -> app.
	go func() { _ = WriteFrame(b, []byte{0x45, 9, 9}) }()
	bufs := [][]byte{make([]byte, 16+1280+64)}
	sizes := []int{0}
	n, err := dev.Read(bufs, sizes, 16)
	if err != nil || n != 1 || !bytes.Equal(bufs[0][16:16+sizes[0]], []byte{0x45, 9, 9}) {
		t.Fatalf("read %d %v %v", n, sizes, err)
	}

	// App -> helper.
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, MaxFrame)
		n, _ := ReadFrame(b, buf)
		got <- buf[:n]
	}()
	pkt := append(make([]byte, 16), 0x45, 1, 2)
	if n, err := dev.Write([][]byte{pkt}, 16); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	select {
	case p := <-got:
		if !bytes.Equal(p, []byte{0x45, 1, 2}) {
			t.Errorf("helper got %v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet")
	}

	// Helper gone: reads fail (the VPN core then ends the session).
	b.Close()
	if _, err := dev.Read(bufs, sizes, 16); err == nil {
		t.Error("read after helper closed")
	}
	_ = dev.Close()
	_ = dev.Close() // a second Close must not panic
}
