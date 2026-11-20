package winvpn

import (
	"encoding/binary"
	"errors"
	"io"
)

// Packet pipe framing: every IP packet is sent as a 2-byte big-endian
// length followed by the packet. Nothing else travels on the packet pipe.

// MaxFrame bounds one packet (the adapter MTU is at most maxMTU).
const MaxFrame = maxMTU + 64

var errFrame = errors.New("bad packet frame")

// WriteFrame writes one packet.
func WriteFrame(w io.Writer, pkt []byte) error {
	if len(pkt) == 0 || len(pkt) > MaxFrame {
		return errFrame
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(pkt)))
	// One write per frame so concurrent writers would never interleave
	// (callers still serialise).
	buf := make([]byte, 0, 2+len(pkt))
	buf = append(buf, hdr[:]...)
	buf = append(buf, pkt...)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one packet into buf (len(buf) >= MaxFrame) and returns
// its length. A zero or oversized length is a protocol error.
func ReadFrame(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > MaxFrame || n > len(buf) {
		return 0, errFrame
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
