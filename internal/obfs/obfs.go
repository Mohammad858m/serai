// Package obfs breaks the traffic-shape fingerprints that get a relay IP
// blocked even when its TLS looks perfect.
//
// A plain tunnel is easy to spot without decrypting anything: the heartbeat is
// always the same number of bytes at the same interval, idle periods are
// perfectly silent, and a bulk transfer is a long run of identically sized
// records. This layer sits between the TLS connection and the multiplexer and
// rewrites that shape:
//
//   - every write is re-chunked into records of random size
//   - every record carries random padding the peer discards
//   - during idle periods, pure-padding records keep a plausible trickle alive
//
// Both peers must enable it with the same settings. It is a shaping layer, not
// a cryptographic one: the TLS beneath it still provides all confidentiality.
package obfs

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Config tunes the shaping. Zero values fall back to the defaults below.
type Config struct {
	// MinChunk and MaxChunk bound the payload slice size per record.
	MinChunk int `json:"min_chunk"`
	MaxChunk int `json:"max_chunk"`
	// MinPad and MaxPad bound the padding appended to each record.
	MinPad int `json:"min_pad"`
	MaxPad int `json:"max_pad"`
	// CoverInterval is the idle gap after which a pure-padding record is sent.
	// Zero disables cover traffic.
	CoverInterval time.Duration `json:"cover_interval"`
	// CoverJitter randomises the cover interval by +/- this fraction (0..1),
	// so the cover itself does not become a periodic signal.
	CoverJitter float64 `json:"cover_jitter"`
}

// Defaults returns a configuration that costs a few percent of bandwidth and
// removes the obvious shape tells.
func Defaults() Config {
	return Config{
		MinChunk:      800,
		MaxChunk:      4096,
		MinPad:        0,
		MaxPad:        255,
		CoverInterval: 7 * time.Second,
		CoverJitter:   0.5,
	}
}

func (c *Config) normalize() {
	d := Defaults()
	if c.MinChunk <= 0 {
		c.MinChunk = d.MinChunk
	}
	if c.MaxChunk <= c.MinChunk {
		c.MaxChunk = c.MinChunk + d.MaxChunk
	}
	if c.MaxChunk > maxRecordPayload {
		c.MaxChunk = maxRecordPayload
	}
	if c.MinPad < 0 {
		c.MinPad = 0
	}
	if c.MaxPad < c.MinPad {
		c.MaxPad = c.MinPad
	}
	if c.MaxPad > maxRecordPad {
		c.MaxPad = maxRecordPad
	}
	if c.CoverJitter < 0 || c.CoverJitter > 1 {
		c.CoverJitter = d.CoverJitter
	}
}

const (
	headerLen        = 4
	maxRecordPayload = 16384
	maxRecordPad     = 4096
)

// ErrBadRecord indicates a malformed record, which on a TLS-protected link
// means a protocol mismatch rather than tampering.
var ErrBadRecord = errors.New("obfs: malformed record")

// Conn wraps a net.Conn with record-level chunking, padding and cover traffic.
type Conn struct {
	net.Conn
	cfg Config

	rnd   *rand.Rand
	rndMu sync.Mutex

	wmu      sync.Mutex
	wbuf     []byte
	wpad     []byte // writer-owned padding source, never shared with the reader
	lastSend time.Time

	rmu       sync.Mutex
	hdr       [headerLen]byte
	remainder []byte // undelivered payload of a partially read record
	scratch   []byte // payload staging area
	rdisc     []byte // padding sink, kept separate so it cannot clobber scratch

	closeOnce sync.Once
	done      chan struct{}
}

// Wrap returns c shaped according to cfg. The returned Conn must be closed to
// stop the cover-traffic goroutine.
func Wrap(c net.Conn, cfg Config) *Conn {
	cfg.normalize()
	o := &Conn{
		Conn:     c,
		cfg:      cfg,
		rnd:      rand.New(rand.NewSource(secureSeed())),
		wbuf:     make([]byte, 0, headerLen+maxRecordPayload+maxRecordPad),
		wpad:     make([]byte, maxRecordPad),
		scratch:  make([]byte, maxRecordPayload),
		rdisc:    make([]byte, 1024),
		lastSend: time.Now(),
		done:     make(chan struct{}),
	}
	if cfg.CoverInterval > 0 {
		go o.coverLoop()
	}
	return o
}

// secureSeed seeds the shaping PRNG from the OS so two peers, or two
// restarts, never produce a correlatable sequence of record sizes.
func secureSeed() int64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return time.Now().UnixNano()
	}
	return int64(binary.BigEndian.Uint64(b[:]))
}

func (o *Conn) intn(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	o.rndMu.Lock()
	defer o.rndMu.Unlock()
	return lo + o.rnd.Intn(hi-lo+1)
}

// Write re-chunks p into randomly sized, randomly padded records.
func (o *Conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := o.intn(o.cfg.MinChunk, o.cfg.MaxChunk)
		if n > len(p) {
			n = len(p)
		}
		if err := o.writeRecord(p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// writeRecord emits one record. A zero-length payload is a cover record.
func (o *Conn) writeRecord(payload []byte) error {
	pad := o.intn(o.cfg.MinPad, o.cfg.MaxPad)

	o.wmu.Lock()
	defer o.wmu.Unlock()

	o.wbuf = o.wbuf[:0]
	var hdr [headerLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], uint16(len(payload)))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(pad))
	o.wbuf = append(o.wbuf, hdr[:]...)
	o.wbuf = append(o.wbuf, payload...)
	if pad > 0 {
		// Padding content is never inspected by the peer; cheap bytes are fine
		// because TLS encrypts the record anyway.
		o.wbuf = append(o.wbuf, o.wpad[:pad]...)
	}

	if _, err := o.Conn.Write(o.wbuf); err != nil {
		return err
	}
	o.lastSend = time.Now()
	return nil
}

// Read delivers payload bytes, transparently skipping padding and cover.
func (o *Conn) Read(p []byte) (int, error) {
	o.rmu.Lock()
	defer o.rmu.Unlock()

	if len(o.remainder) > 0 {
		n := copy(p, o.remainder)
		o.remainder = o.remainder[n:]
		return n, nil
	}

	for {
		if _, err := io.ReadFull(o.Conn, o.hdr[:]); err != nil {
			return 0, err
		}
		plen := int(binary.BigEndian.Uint16(o.hdr[0:2]))
		padLen := int(binary.BigEndian.Uint16(o.hdr[2:4]))
		if plen > maxRecordPayload || padLen > maxRecordPad {
			return 0, ErrBadRecord
		}

		if plen > 0 {
			buf := o.scratch[:plen]
			if _, err := io.ReadFull(o.Conn, buf); err != nil {
				return 0, err
			}
			if padLen > 0 {
				if err := o.discard(padLen); err != nil {
					return 0, err
				}
			}
			n := copy(p, buf)
			if n < plen {
				// Keep the tail for the next Read rather than losing it.
				o.remainder = append(o.remainder[:0], buf[n:]...)
			}
			return n, nil
		}

		// Cover record: drop it and keep waiting for real payload.
		if padLen > 0 {
			if err := o.discard(padLen); err != nil {
				return 0, err
			}
		}
	}
}

func (o *Conn) discard(n int) error {
	for n > 0 {
		chunk := n
		if chunk > len(o.rdisc) {
			chunk = len(o.rdisc)
		}
		if _, err := io.ReadFull(o.Conn, o.rdisc[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// coverLoop emits a padding-only record whenever the link has been quiet, so
// an idle tunnel looks like a web app with a chatty websocket instead of a
// dead connection that wakes up only when its owner browses.
func (o *Conn) coverLoop() {
	for {
		o.wmu.Lock()
		idle := time.Since(o.lastSend)
		o.wmu.Unlock()

		wait := o.jitteredInterval() - idle
		if wait <= 0 {
			if err := o.writeRecord(nil); err != nil {
				return
			}
			wait = o.jitteredInterval()
		}

		select {
		case <-time.After(wait):
		case <-o.done:
			return
		}
	}
}

func (o *Conn) jitteredInterval() time.Duration {
	base := float64(o.cfg.CoverInterval)
	if o.cfg.CoverJitter == 0 {
		return time.Duration(base)
	}
	o.rndMu.Lock()
	f := o.rnd.Float64()*2 - 1 // [-1, 1)
	o.rndMu.Unlock()
	return time.Duration(base * (1 + f*o.cfg.CoverJitter))
}

// Close stops cover traffic and closes the underlying connection.
func (o *Conn) Close() error {
	o.closeOnce.Do(func() { close(o.done) })
	return o.Conn.Close()
}
