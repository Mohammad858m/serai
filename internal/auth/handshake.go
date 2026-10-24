// Package auth implements the mutual pre-shared-key handshake that runs on top
// of an already-encrypted carrier (TLS 1.3 or QUIC).
//
// The transport provides confidentiality; this handshake provides
// authentication and, just as importantly, makes the server silent to
// unauthenticated probes: a peer that cannot produce a valid MAC never learns
// that a tunnel lives behind the port.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Version is the wire version of the handshake.
const Version uint8 = 1

var magic = [4]byte{'M', 'T', 'N', 'L'}

// Flags carried in HELLO.
const (
	// FlagDatagram means the client can carry packets over unreliable datagrams.
	FlagDatagram uint8 = 1 << 0
)

// Status codes carried in WELCOME.
const (
	StatusOK          uint8 = 0
	StatusBadVersion  uint8 = 1
	StatusUnknownKey  uint8 = 2
	StatusBadMAC      uint8 = 3
	StatusReplay      uint8 = 4
	StatusUnavailable uint8 = 5
)

const (
	helloHeadLen   = 4 + 1 + 1 + 32 + 8 + 8 + 2 // 56
	welcomeHeadLen = 4 + 1 + 1 + 32 + 2         // 40
	macLen         = 32
	maxPayload     = 8192

	// ClockSkew is how far a HELLO timestamp may deviate from server time.
	ClockSkew = 90 * time.Second
)

var (
	ErrBadMagic   = errors.New("auth: bad magic")
	ErrBadVersion = errors.New("auth: unsupported version")
	ErrBadMAC     = errors.New("auth: authentication failed")
	ErrReplay     = errors.New("auth: replayed or stale handshake")
	ErrPayload    = errors.New("auth: payload too large")
)

// Credentials is one identity: a key id derived from the PSK, plus the PSK.
type Credentials struct {
	KeyID [8]byte
	PSK   []byte
}

// NewCredentials derives the public key id from a pre-shared key.
func NewCredentials(psk []byte) Credentials {
	c := Credentials{PSK: append([]byte(nil), psk...)}
	h := sha256.New()
	h.Write([]byte("mtunnel/keyid/v1"))
	h.Write(psk)
	copy(c.KeyID[:], h.Sum(nil))
	return c
}

// KeyIDString renders the key id for logs and config files.
func (c Credentials) KeyIDString() string { return hex.EncodeToString(c.KeyID[:]) }

// Hello is the client's opening message.
type Hello struct {
	Flags     uint8
	Random    [32]byte
	KeyID     [8]byte
	Timestamp int64 // unix milliseconds
	Payload   []byte
}

// Result is what both sides learn once the handshake completes.
type Result struct {
	SessionID [16]byte
	Flags     uint8
	Payload   []byte // peer-supplied payload (JSON in this implementation)
}

// SessionIDString renders the session id for logs.
func (r Result) SessionIDString() string { return hex.EncodeToString(r.SessionID[:]) }

func tagOf(psk, data []byte) [32]byte {
	m := hmac.New(sha256.New, psk)
	m.Write(data)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

func deriveSessionID(psk []byte, clientRandom, serverRandom [32]byte) [16]byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte("mtunnel/session/v1"))
	m.Write(clientRandom[:])
	m.Write(serverRandom[:])
	var out [16]byte
	copy(out[:], m.Sum(nil))
	return out
}

// marshalHelloHead returns the MAC-covered prefix of a HELLO.
func marshalHelloHead(h Hello) []byte {
	b := make([]byte, 0, helloHeadLen+len(h.Payload))
	b = append(b, magic[:]...)
	b = append(b, Version, h.Flags)
	b = append(b, h.Random[:]...)
	b = append(b, h.KeyID[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(h.Timestamp))
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.Payload)))
	b = append(b, h.Payload...)
	return b
}

// ClientHandshake performs the client half of the handshake over rw.
func ClientHandshake(rw io.ReadWriter, cred Credentials, flags uint8, payload []byte) (Result, error) {
	if len(payload) > maxPayload {
		return Result{}, ErrPayload
	}

	h := Hello{
		Flags:     flags,
		KeyID:     cred.KeyID,
		Timestamp: time.Now().UnixMilli(),
		Payload:   payload,
	}
	if _, err := rand.Read(h.Random[:]); err != nil {
		return Result{}, err
	}

	body := marshalHelloHead(h)
	tag := tagOf(cred.PSK, body)
	if _, err := rw.Write(append(body, tag[:]...)); err != nil {
		return Result{}, fmt.Errorf("auth: write hello: %w", err)
	}

	head := make([]byte, welcomeHeadLen)
	if _, err := io.ReadFull(rw, head); err != nil {
		return Result{}, fmt.Errorf("auth: read welcome: %w", err)
	}
	if !bytesEqual(head[0:4], magic[:]) {
		return Result{}, ErrBadMagic
	}
	if head[4] != Version {
		return Result{}, ErrBadVersion
	}
	status := head[5]
	var serverRandom [32]byte
	copy(serverRandom[:], head[6:38])
	plen := int(binary.BigEndian.Uint16(head[38:40]))
	if plen > maxPayload {
		return Result{}, ErrPayload
	}

	rest := make([]byte, plen+macLen)
	if _, err := io.ReadFull(rw, rest); err != nil {
		return Result{}, fmt.Errorf("auth: read welcome payload: %w", err)
	}
	welcomePayload := rest[:plen]

	// The server MAC binds the reply to our HELLO random, so a recorded
	// WELCOME cannot be replayed against a fresh HELLO.
	signed := make([]byte, 0, len(head)+plen+32)
	signed = append(signed, head...)
	signed = append(signed, welcomePayload...)
	signed = append(signed, h.Random[:]...)
	want := tagOf(cred.PSK, signed)
	if subtle.ConstantTimeCompare(want[:], rest[plen:]) != 1 {
		return Result{}, ErrBadMAC
	}
	if status != StatusOK {
		return Result{}, fmt.Errorf("auth: server refused session (status %d)", status)
	}

	return Result{
		SessionID: deriveSessionID(cred.PSK, h.Random, serverRandom),
		Flags:     h.Flags,
		Payload:   welcomePayload,
	}, nil
}

// KeyLookup resolves a key id to credentials. Returning ok=false makes the
// server treat the peer as an unauthenticated probe.
type KeyLookup func(keyID [8]byte) (Credentials, bool)

// ServerResponder builds the WELCOME payload for an authenticated HELLO.
// Returning a non-OK status rejects the session but still answers with a valid
// MAC, so a legitimate client gets a real error instead of a dangling socket.
type ServerResponder func(h Hello, res Result) (status uint8, payload []byte, err error)

// ServerHandshake performs the server half of the handshake over rw.
//
// On authentication failure it returns an error without writing anything: the
// caller should then hand the connection to a decoy handler so the port stays
// indistinguishable from an ordinary web server.
func ServerHandshake(rw io.ReadWriter, lookup KeyLookup, replay *ReplayGuard, respond ServerResponder) (Result, error) {
	head := make([]byte, helloHeadLen)
	if _, err := io.ReadFull(rw, head); err != nil {
		return Result{}, fmt.Errorf("auth: read hello: %w", err)
	}
	if !bytesEqual(head[0:4], magic[:]) {
		return Result{}, ErrBadMagic
	}
	if head[4] != Version {
		return Result{}, ErrBadVersion
	}

	var h Hello
	h.Flags = head[5]
	copy(h.Random[:], head[6:38])
	copy(h.KeyID[:], head[38:46])
	h.Timestamp = int64(binary.BigEndian.Uint64(head[46:54]))
	plen := int(binary.BigEndian.Uint16(head[54:56]))
	if plen > maxPayload {
		return Result{}, ErrPayload
	}

	rest := make([]byte, plen+macLen)
	if _, err := io.ReadFull(rw, rest); err != nil {
		return Result{}, fmt.Errorf("auth: read hello payload: %w", err)
	}
	h.Payload = rest[:plen]

	signed := make([]byte, 0, len(head)+plen)
	signed = append(signed, head...)
	signed = append(signed, h.Payload...)

	cred, ok := lookup(h.KeyID)
	if !ok {
		// Spend the same work as a real verification so timing does not
		// distinguish "unknown key" from "bad MAC".
		_ = tagOf(make([]byte, 32), signed)
		return Result{}, ErrBadMAC
	}
	want := tagOf(cred.PSK, signed)
	if subtle.ConstantTimeCompare(want[:], rest[plen:]) != 1 {
		return Result{}, ErrBadMAC
	}
	if replay != nil && !replay.Admit(h.Random, time.UnixMilli(h.Timestamp)) {
		return Result{}, ErrReplay
	}

	var serverRandom [32]byte
	if _, err := rand.Read(serverRandom[:]); err != nil {
		return Result{}, err
	}
	res := Result{
		SessionID: deriveSessionID(cred.PSK, h.Random, serverRandom),
		Flags:     h.Flags,
		Payload:   h.Payload,
	}

	status := StatusOK
	var payload []byte
	if respond != nil {
		var err error
		status, payload, err = respond(h, res)
		if err != nil {
			status, payload = StatusUnavailable, nil
		}
	}
	if len(payload) > maxPayload {
		return Result{}, ErrPayload
	}

	out := make([]byte, 0, welcomeHeadLen+len(payload)+macLen)
	out = append(out, magic[:]...)
	out = append(out, Version, status)
	out = append(out, serverRandom[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload)))
	out = append(out, payload...)

	signedReply := make([]byte, 0, len(out)+32)
	signedReply = append(signedReply, out...)
	signedReply = append(signedReply, h.Random[:]...)
	tag := tagOf(cred.PSK, signedReply)
	out = append(out, tag[:]...)

	if _, err := rw.Write(out); err != nil {
		return Result{}, fmt.Errorf("auth: write welcome: %w", err)
	}
	if status != StatusOK {
		return Result{}, fmt.Errorf("auth: session refused (status %d)", status)
	}
	return res, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ReplayGuard rejects a HELLO whose random was already used, within a bounded
// time window. Combined with the timestamp check this keeps memory cost
// proportional to the handshake rate rather than to uptime.
type ReplayGuard struct {
	mu     sync.Mutex
	seen   map[[32]byte]time.Time
	window time.Duration
	swept  time.Time
}

// NewReplayGuard returns a guard that remembers randoms for 2*ClockSkew.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: make(map[[32]byte]time.Time), window: 2 * ClockSkew}
}

// Admit reports whether this (random, timestamp) pair is fresh and unseen.
func (g *ReplayGuard) Admit(random [32]byte, ts time.Time) bool {
	now := time.Now()
	if d := now.Sub(ts); d > ClockSkew || d < -ClockSkew {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if now.Sub(g.swept) > g.window/4 {
		for k, v := range g.seen {
			if now.Sub(v) > g.window {
				delete(g.seen, k)
			}
		}
		g.swept = now
	}
	if _, dup := g.seen[random]; dup {
		return false
	}
	g.seen[random] = now
	return true
}
