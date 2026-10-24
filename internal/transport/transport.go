// Package transport abstracts the ways a client can reach the server.
//
// Every transport yields a Carrier: an encrypted, authenticated-at-the-TLS-layer
// connection that can host several independent streams and, where the protocol
// allows it, unreliable datagrams. Everything above this package is written
// once against Carrier and works unchanged over QUIC, TLS/TCP or WebSocket.
package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/Mohammad858m/serai/internal/obfs"
)

// ALPN is the protocol name used for a direct (non-HTTP) mtunnel carrier.
const ALPN = "mtnl/1"

// WebSocketPath is where the server accepts WebSocket upgrades.
const WebSocketPath = "/ws"

// ErrNoDatagrams is returned by Carrier.SendDatagram on stream-only transports.
var ErrNoDatagrams = errors.New("transport: datagrams not supported")

// Stream is one bidirectional, reliable, ordered byte stream in a Carrier.
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// Carrier is an established path to the peer.
type Carrier interface {
	// OpenStream opens a new stream towards the peer.
	OpenStream(ctx context.Context) (Stream, error)
	// AcceptStream waits for the peer to open a stream.
	AcceptStream(ctx context.Context) (Stream, error)

	// SendDatagram sends one unreliable datagram. It returns ErrNoDatagrams on
	// transports without datagram support, and the caller is expected to fall
	// back to a stream.
	SendDatagram(b []byte) error
	// ReceiveDatagram blocks for the next datagram.
	ReceiveDatagram(ctx context.Context) ([]byte, error)

	// MaxDatagramSize is the largest datagram that will fit, or 0 if unsupported.
	MaxDatagramSize() int

	LocalAddr() net.Addr
	RemoteAddr() net.Addr

	// Done is closed when the carrier dies for any reason.
	Done() <-chan struct{}

	// Transport names the transport that produced this carrier, for logs and
	// for the dial scoreboard.
	Transport() string

	Close() error
}

// Role says what a path is suited for. Splitting the two is what lets a
// deployment put the cheap, censorship-resistant path (a CDN-fronted
// WebSocket) in charge of staying registered, while bulk traffic takes the
// direct path at full speed and zero CDN cost.
type Role string

const (
	// RoleBoth carries control and bulk traffic.
	RoleBoth Role = "both"
	// RoleBootstrap carries only the control stream: a few bytes per minute.
	RoleBootstrap Role = "bootstrap"
	// RoleData carries bulk forwarded traffic.
	RoleData Role = "data"
)

// CarriesData reports whether forwarded connections may use this role.
func (r Role) CarriesData() bool { return r != RoleBootstrap }

// CarriesControl reports whether the control stream may use this role.
func (r Role) CarriesControl() bool { return r != RoleData }

// Dialer establishes one Carrier. Implementations must honour ctx: the racer
// cancels every losing attempt the moment one candidate wins.
type Dialer interface {
	// Name identifies this candidate in logs and in the scoreboard. It must be
	// stable across restarts.
	Name() string
	Dial(ctx context.Context) (Carrier, error)
}

// Listener accepts Carriers on the server side.
type Listener interface {
	Name() string
	Accept(ctx context.Context) (Carrier, error)
	Addr() net.Addr
	Close() error
}

// --- yamux-backed carrier, used by every single-connection transport ---------

// MuxOptions tunes a mux carrier. The defaults are deliberately modest: see
// StreamWindow for why a bigger number is not automatically better.
type MuxOptions struct {
	// Obfs shapes the connection beneath the multiplexer. Both peers must
	// agree; nil disables shaping.
	Obfs *obfs.Config

	// StreamWindow is the per-stream receive window in bytes.
	//
	// A single stream cannot exceed window/RTT, so 256 KiB (the library
	// default) caps one flow at about 10 Mbit/s over a 200 ms path. The
	// tempting fix is a very large window, but this is a *per-stream* buffer
	// ceiling: window x concurrent streams x carriers is the worst-case
	// memory this process can be made to hold, and a relay with a thousand
	// live flows will find that ceiling.
	//
	// For VPN traffic -- many concurrent, mostly small flows -- aggregate
	// throughput comes from concurrency and from running several carriers, not
	// from a large window, so 1-4 MiB is the right range. Raise it only for a
	// workload of a few very fat flows, and only with the RAM to back it.
	StreamWindow int

	// MaxStreams caps concurrent streams per carrier, which is what turns the
	// memory ceiling above from theoretical into bounded. Zero uses 256.
	MaxStreams int
}

func (o MuxOptions) yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	// The session layer runs its own keepalive on the control stream, with
	// jitter; yamux's fixed-interval ping would be a timing fingerprint.
	c.EnableKeepAlive = false
	c.ConnectionWriteTimeout = 15 * time.Second
	c.StreamOpenTimeout = 20 * time.Second
	c.StreamCloseTimeout = 2 * time.Minute
	c.LogOutput = io.Discard

	window := o.StreamWindow
	if window <= 0 {
		window = 2 << 20
	}
	if window < 256<<10 {
		window = 256 << 10 // yamux rejects anything smaller
	}
	c.MaxStreamWindowSize = uint32(window)

	backlog := o.MaxStreams
	if backlog <= 0 {
		backlog = 256
	}
	c.AcceptBacklog = backlog
	return c
}

// muxCarrier adapts a plain net.Conn into a Carrier by multiplexing yamux over
// it. Datagrams are not available: a reliable byte stream cannot drop packets,
// which is exactly why QUIC is preferred when it is reachable.
type muxCarrier struct {
	name    string
	conn    net.Conn
	session *yamux.Session
}

// NewMuxCarrier wraps conn. isClient selects the yamux role; the two sides must
// disagree, so the dialing side passes true.
//
// When opts.Obfs is non-nil the connection is shaped before yamux sees it, so
// the record sizes and idle pattern on the wire no longer betray a tunnel.
// Both peers must pass equivalent settings.
func NewMuxCarrier(name string, conn net.Conn, isClient bool, opts MuxOptions) (Carrier, error) {
	if opts.Obfs != nil {
		conn = obfs.Wrap(conn, *opts.Obfs)
	}
	cfg := opts.yamuxConfig()
	var (
		s   *yamux.Session
		err error
	)
	if isClient {
		s, err = yamux.Client(conn, cfg)
	} else {
		s, err = yamux.Server(conn, cfg)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &muxCarrier{name: name, conn: conn, session: s}, nil
}

func (m *muxCarrier) OpenStream(ctx context.Context) (Stream, error) {
	return awaitStream(ctx, m.session.Open)
}

func (m *muxCarrier) AcceptStream(ctx context.Context) (Stream, error) {
	return awaitStream(ctx, m.session.Accept)
}

// awaitStream bridges yamux's blocking, context-free API to a context-aware
// one. If ctx fires first the in-flight stream is closed rather than leaked.
func awaitStream(ctx context.Context, fn func() (net.Conn, error)) (Stream, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := fn()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		return r.c, nil
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.err == nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func (m *muxCarrier) SendDatagram([]byte) error { return ErrNoDatagrams }

func (m *muxCarrier) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	// Block until cancelled: the datapath runs a receive loop unconditionally,
	// and returning an error immediately would spin it.
	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *muxCarrier) MaxDatagramSize() int     { return 0 }
func (m *muxCarrier) LocalAddr() net.Addr      { return m.conn.LocalAddr() }
func (m *muxCarrier) RemoteAddr() net.Addr     { return m.conn.RemoteAddr() }
func (m *muxCarrier) Done() <-chan struct{}    { return m.session.CloseChan() }
func (m *muxCarrier) Transport() string        { return m.name }
func (m *muxCarrier) Close() error             { return m.session.Close() }
