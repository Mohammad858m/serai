// Package sniff peeks at a TLS ClientHello without terminating the handshake.
//
// This is what lets the relay expose exactly one port. A VPN user's TLS
// session must terminate on Xray, not on the relay, so the relay cannot
// decrypt anything -- but it can read the plaintext SNI in the first record
// and decide where to send the bytes:
//
//	SNI == the tunnel's own name  -> terminate locally (tunnel + decoy site)
//	SNI == a configured inbound   -> forward raw bytes over the tunnel
//	anything else                 -> the decoy
//
// From outside, the host has 443 open and serves a website. There is no second
// port to find, and no cluster of odd high ports that marks a relay even when
// every individual connection looks clean.
package sniff

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

var (
	// ErrNotTLS means the first bytes are not a TLS handshake record.
	ErrNotTLS = errors.New("sniff: not a TLS handshake")
	// ErrNoSNI means the ClientHello carried no server_name extension.
	ErrNoSNI = errors.New("sniff: no SNI in ClientHello")
	// ErrTooLarge guards against a bogus length field.
	ErrTooLarge = errors.New("sniff: ClientHello too large")
)

const maxHello = 16384

// Conn is a net.Conn whose already-consumed prefix is replayed on Read, so the
// bytes used for sniffing can still be handed to a TLS server or forwarded
// verbatim to the real backend.
type Conn struct {
	net.Conn
	r *bufio.Reader
}

// Read serves buffered bytes first, then the live connection.
func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// ServerName reads just enough of the connection to extract the SNI and
// returns a Conn that still yields the full byte stream from the beginning.
//
// A connection with no SNI, or one that is not TLS at all, is returned intact
// alongside the error so the caller can still route it to the decoy.
func ServerName(c net.Conn, timeout time.Duration) (string, *Conn, error) {
	if timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		defer c.SetReadDeadline(time.Time{})
	}

	br := bufio.NewReaderSize(c, maxHello+512)
	wrapped := &Conn{Conn: c, r: br}

	// TLS record header: type(1) version(2) length(2).
	hdr, err := br.Peek(5)
	if err != nil {
		return "", wrapped, err
	}
	if hdr[0] != 0x16 { // handshake
		return "", wrapped, ErrNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > maxHello {
		return "", wrapped, ErrTooLarge
	}

	buf, err := br.Peek(5 + recLen)
	if err != nil {
		return "", wrapped, err
	}
	name, err := parseClientHello(buf[5 : 5+recLen])
	return name, wrapped, err
}

// parseClientHello walks a handshake record and returns the SNI host.
func parseClientHello(b []byte) (string, error) {
	// Handshake header: type(1) length(3).
	if len(b) < 4 || b[0] != 0x01 { // client_hello
		return "", ErrNotTLS
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	if hsLen > len(b) {
		// The ClientHello spans more than one record; the SNI is normally well
		// inside the first, so parse what we have and let it fail if truncated.
		hsLen = len(b)
	}
	b = b[:hsLen]

	// client_version(2) + random(32)
	if len(b) < 34 {
		return "", ErrNotTLS
	}
	b = b[34:]

	// legacy_session_id
	if len(b) < 1 {
		return "", ErrNotTLS
	}
	n := int(b[0])
	if len(b) < 1+n {
		return "", ErrNotTLS
	}
	b = b[1+n:]

	// cipher_suites
	if len(b) < 2 {
		return "", ErrNotTLS
	}
	n = int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < 2+n {
		return "", ErrNotTLS
	}
	b = b[2+n:]

	// compression_methods
	if len(b) < 1 {
		return "", ErrNotTLS
	}
	n = int(b[0])
	if len(b) < 1+n {
		return "", ErrNotTLS
	}
	b = b[1+n:]

	// extensions
	if len(b) < 2 {
		return "", ErrNoSNI
	}
	extTotal := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if extTotal > len(b) {
		extTotal = len(b)
	}
	b = b[:extTotal]

	for len(b) >= 4 {
		extType := binary.BigEndian.Uint16(b[0:2])
		extLen := int(binary.BigEndian.Uint16(b[2:4]))
		b = b[4:]
		if extLen > len(b) {
			return "", ErrNoSNI
		}
		if extType == 0x0000 { // server_name
			return parseSNIExtension(b[:extLen])
		}
		b = b[extLen:]
	}
	return "", ErrNoSNI
}

func parseSNIExtension(b []byte) (string, error) {
	// server_name_list length(2), then entries of type(1) length(2) value.
	if len(b) < 2 {
		return "", ErrNoSNI
	}
	listLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if listLen > len(b) {
		listLen = len(b)
	}
	b = b[:listLen]

	for len(b) >= 3 {
		nameType := b[0]
		nameLen := int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if nameLen > len(b) {
			return "", ErrNoSNI
		}
		if nameType == 0x00 { // host_name
			return string(b[:nameLen]), nil
		}
		b = b[nameLen:]
	}
	return "", ErrNoSNI
}

// Prefixed returns a Conn that replays pre before reading from c. It is useful
// when a caller has already consumed bytes by other means.
func Prefixed(c net.Conn, pre []byte) *Conn {
	return &Conn{Conn: c, r: bufio.NewReader(io.MultiReader(bytesReader(pre), c))}
}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
