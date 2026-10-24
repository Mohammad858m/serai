// Package protocol defines the control-plane messages exchanged between the
// origin (the server that owns the panel, usually abroad) and the edge (the
// relay users actually connect to).
//
// Direction is the whole point of this design: the origin dials the edge. The
// edge never has to reach a filtered address, and the origin needs no inbound
// firewall rule at all.
package protocol

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Version is the control-plane version, carried in Register.
const Version = "1"

// Proto names a forwarded L4 protocol.
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Forward is one port-forwarding rule, declared by the origin and opened by
// the edge. Keeping the rules in the origin's config means the whole tunnel is
// configured on the machine that already runs the panel; the edge is a relay
// that holds nothing but a key and a port.
type Forward struct {
	// Name identifies the rule. The edge quotes it back when opening a data
	// stream, and the origin resolves the real target from its own config, so
	// a compromised edge can never redirect traffic to an arbitrary host.
	Name string `json:"name"`

	// Proto is "tcp", "udp", or "tcp+udp".
	Proto string `json:"proto"`

	// EdgePorts is the port set to open on the edge: a comma-separated list of
	// single ports and inclusive ranges, e.g. "443,8443,20000-20100".
	EdgePorts string `json:"edge_ports"`

	// Ports is the expanded, validated form of EdgePorts.
	Ports []int `json:"ports,omitempty"`

	// SNI lists hostnames that route to this rule on the edge's shared 443.
	// Using SNI instead of a dedicated port is what keeps the relay down to a
	// single open port: the user's TLS still terminates on Xray, because the
	// edge only reads the plaintext server name and forwards the bytes.
	SNI []string `json:"sni,omitempty"`

	// ProxyProtocol is 0 (off), 1, or 2. When non-zero the origin prefixes a
	// PROXY protocol header to the target connection so Xray/3x-ui logs the
	// real client IP instead of 127.0.0.1.
	ProxyProtocol int `json:"proxy_protocol,omitempty"`

	// Target is the fixed backend for a single-port rule, as host:port.
	// It is never sent to the edge: see Public.
	Target string `json:"target,omitempty"`

	// TargetHost is the backend host for a multi-port rule; the edge port is
	// reused as the backend port, so a panel inbound on 20001 lands on 20001.
	// It is never sent to the edge: see Public.
	TargetHost string `json:"target_host,omitempty"`
}

// Public returns the rule as the edge should see it: no backend addresses.
//
// The edge quotes a rule name and a port back to the origin, and the origin
// resolves the real backend from its own config. A relay that is seized or
// compromised therefore cannot be told to open a connection to an arbitrary
// host -- it can only ask for backends the origin already chose to expose.
func (f Forward) Public() Forward {
	f.Target = ""
	f.TargetHost = ""
	return f
}

// Resolve maps an edge port to the backend address for this rule.
func (f Forward) Resolve(port int) (string, error) {
	if f.Target != "" {
		return f.Target, nil
	}
	if f.TargetHost == "" {
		return "", fmt.Errorf("protocol: forward %q has no target", f.Name)
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("protocol: forward %q got invalid port %d", f.Name, port)
	}
	return net.JoinHostPort(f.TargetHost, strconv.Itoa(port)), nil
}

// WantsTCP reports whether the rule covers TCP.
func (f Forward) WantsTCP() bool { return f.Proto == "tcp" || f.Proto == "tcp+udp" || f.Proto == "" }

// WantsUDP reports whether the rule covers UDP.
func (f Forward) WantsUDP() bool { return f.Proto == "udp" || f.Proto == "tcp+udp" }

// Register is the origin's opening request, carried in the HELLO payload.
type Register struct {
	Version  string    `json:"version"`
	Origin   string    `json:"origin"`
	Forwards []Forward `json:"forwards"`
	// Keepalive is the interval, in seconds, at which the origin will ping.
	Keepalive int `json:"keepalive"`
	// Takeover asks the edge to evict an existing session with the same origin
	// name instead of refusing the new one. This is what makes a reconnect
	// after a dead TCP connection instant rather than waiting for a timeout.
	Takeover bool `json:"takeover"`

	// Join attaches this carrier to an existing session instead of creating
	// one, which is how a tunnel ends up with several carriers over several
	// transports while the relay still sees a single set of forwarded ports.
	// An unknown or expired token is not an error: the relay falls back to a
	// fresh registration using Forwards and returns the new token.
	Join string `json:"join,omitempty"`
}

// Accepted reports one rule the edge actually bound.
type Accepted struct {
	Name  string `json:"name"`
	Proto string `json:"proto"`
	Ports []int  `json:"ports"`
}

// Rejected reports one rule the edge refused, with a human-readable reason.
type Rejected struct {
	Name   string `json:"name"`
	Ports  []int  `json:"ports,omitempty"`
	Reason string `json:"reason"`
}

// Registered is the edge's reply, carried in the WELCOME payload.
type Registered struct {
	Version string `json:"version"`
	Edge    string `json:"edge"`
	// Token identifies the session so further carriers can Join it.
	Token    string     `json:"token"`
	Accepted []Accepted `json:"accepted"`
	Rejected []Rejected `json:"rejected,omitempty"`
	// Joined is true when this carrier attached to an existing session.
	Joined bool `json:"joined,omitempty"`
}

// OpenRequest is the header the edge writes on a new data stream.
type OpenRequest struct {
	Forward string `json:"f"`
	Proto   Proto  `json:"p"`
	// Port is the edge port the client hit; the origin maps it to its target.
	Port int `json:"port"`
	// Client is the user's address, used for the PROXY protocol header and logs.
	Client string `json:"c"`
}

// OpenResponse is the origin's answer before data starts flowing.
type OpenResponse struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Control message types sent as JSON lines on the control stream.
const (
	MsgPing = "ping"
	MsgPong = "pong"
	MsgBye  = "bye"
)

// Control is one control-stream message.
type Control struct {
	Type   string `json:"t"`
	Seq    uint64 `json:"seq,omitempty"`
	TS     int64  `json:"ts,omitempty"` // unix milliseconds
	Reason string `json:"reason,omitempty"`
}

// maxLine bounds a single JSON line so a hostile peer cannot exhaust memory.
const maxLine = 1 << 20

// ErrLineTooLong is returned when a peer sends an oversized JSON line.
var ErrLineTooLong = errors.New("protocol: control line too long")

// Codec reads and writes newline-delimited JSON on a stream.
type Codec struct {
	r *bufio.Reader
	w io.Writer
}

// NewCodec wraps a stream.
func NewCodec(rw io.ReadWriter) *Codec {
	return &Codec{r: bufio.NewReaderSize(rw, 8192), w: rw}
}

// Read decodes the next JSON line into v.
func (c *Codec) Read(v any) error {
	line, err := c.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return ErrLineTooLong
	}
	if err != nil {
		return err
	}
	if len(line) > maxLine {
		return ErrLineTooLong
	}
	return json.Unmarshal(line, v)
}

// Write encodes v as a single JSON line.
func (c *Codec) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := c.w.Write(b); err != nil {
		return fmt.Errorf("protocol: write: %w", err)
	}
	return nil
}

// Now returns the current time in the units used by Control.TS.
func Now() int64 { return time.Now().UnixMilli() }
