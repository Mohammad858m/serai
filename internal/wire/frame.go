// Package wire implements the length-prefixed packet codec used by the
// stream datapath. One frame is exactly one IP packet.
package wire

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// MaxPacketSize bounds a single IP packet carried over a stream.
const MaxPacketSize = 65535

var (
	// ErrPacketTooLarge is returned when a packet does not fit a frame.
	ErrPacketTooLarge = errors.New("wire: packet exceeds maximum frame size")
	// ErrShortFrame indicates a frame header advertising a zero-length body.
	ErrShortFrame = errors.New("wire: zero-length frame")
)

// Framer multiplexes packet reads and writes over a single stream. Reads and
// writes are independently locked so one direction never blocks the other.
type Framer struct {
	rmu sync.Mutex
	r   *bufio.Reader

	wmu sync.Mutex
	w   *bufio.Writer
	hdr [2]byte
}

// NewFramer wraps rw with buffers sized for a few full-MTU packets.
func NewFramer(rw io.ReadWriter, bufSize int) *Framer {
	if bufSize < 4096 {
		bufSize = 4096
	}
	return &Framer{
		r: bufio.NewReaderSize(rw, bufSize),
		w: bufio.NewWriterSize(rw, bufSize),
	}
}

// ReadPacket reads one packet into buf. buf must be large enough to hold the
// advertised frame; otherwise io.ErrShortBuffer is returned and the frame is
// consumed so the stream stays in sync.
func (f *Framer) ReadPacket(buf []byte) (int, error) {
	f.rmu.Lock()
	defer f.rmu.Unlock()

	var hdr [2]byte
	if _, err := io.ReadFull(f.r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return 0, ErrShortFrame
	}
	if n > len(buf) {
		// Drain the body to keep framing aligned before reporting the error.
		if _, err := f.r.Discard(n); err != nil {
			return 0, err
		}
		return 0, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(f.r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

// WritePacket buffers one packet. Call Flush to push it onto the wire.
func (f *Framer) WritePacket(p []byte) error {
	if len(p) == 0 {
		return ErrShortFrame
	}
	if len(p) > MaxPacketSize {
		return ErrPacketTooLarge
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()

	binary.BigEndian.PutUint16(f.hdr[:], uint16(len(p)))
	if _, err := f.w.Write(f.hdr[:]); err != nil {
		return err
	}
	_, err := f.w.Write(p)
	return err
}

// Flush pushes buffered frames to the underlying stream.
func (f *Framer) Flush() error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	return f.w.Flush()
}

// WriteAndFlush is the convenience path for a single packet.
func (f *Framer) WriteAndFlush(p []byte) error {
	if err := f.WritePacket(p); err != nil {
		return err
	}
	return f.Flush()
}
