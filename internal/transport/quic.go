package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicMaxDatagram is a conservative cap that survives almost every path
// without IP fragmentation. Datagrams larger than this fall back to a stream.
const quicMaxDatagram = 1200

func quicConfig(keepalive time.Duration) *quic.Config {
	return &quic.Config{
		EnableDatagrams:      true,
		KeepAlivePeriod:      keepalive,
		MaxIdleTimeout:       3 * keepalive,
		HandshakeIdleTimeout: 8 * time.Second,
		MaxIncomingStreams:   64,
		InitialPacketSize:    1350,
	}
}

// QUICDialer dials the server over QUIC. This is the preferred transport: it
// multiplexes natively, survives packet loss without head-of-line blocking,
// and carries the datapath over unreliable datagrams so a tunnelled TCP flow
// is never retransmitted twice (the "TCP over TCP meltdown").
type QUICDialer struct {
	// Addr is host:port of the relay's UDP listener.
	Addr string
	// ServerName is the SNI and the name verified on the certificate.
	ServerName string
	// RootCAs pins acceptable issuers; nil uses the system pool.
	RootCAs *x509.CertPool
	// PinnedSPKI pins the relay's public key.
	PinnedSPKI []string
	// Insecure disables certificate verification; requires PinnedSPKI.
	Insecure bool
	// Keepalive drives both the QUIC keepalive and the idle timeout.
	Keepalive time.Duration
}

func (d *QUICDialer) Name() string { return "quic" }

func (d *QUICDialer) Dial(ctx context.Context) (Carrier, error) {
	// QUIC carries its own TLS stack, so the uTLS mimicry used on the TCP
	// paths does not apply here. That is acceptable: HTTP/3 is ubiquitous
	// enough that a QUIC flow to 443 is unremarkable on its own, and where
	// UDP is blocked or inspected the racer falls back to the WebSocket path.
	tlsConf := &tls.Config{
		ServerName:         d.ServerName,
		RootCAs:            d.RootCAs,
		InsecureSkipVerify: d.Insecure || len(d.PinnedSPKI) > 0,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
	}
	if len(d.PinnedSPKI) > 0 {
		pins := d.PinnedSPKI
		tlsConf.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			return checkPins(raw, pins)
		}
	}

	ka := d.Keepalive
	if ka <= 0 {
		ka = 10 * time.Second
	}

	conn, err := quic.DialAddr(ctx, d.Addr, tlsConf, quicConfig(ka))
	if err != nil {
		return nil, err
	}
	return &quicCarrier{conn: conn}, nil
}

// QUICListener accepts QUIC carriers.
type QUICListener struct {
	ln *quic.Listener
}

// ListenQUIC binds addr (UDP) and accepts mtunnel carriers on it.
func ListenQUIC(addr string, tlsConf *tls.Config, keepalive time.Duration) (*QUICListener, error) {
	conf := cloneTLS(tlsConf)
	conf.NextProtos = []string{ALPN}

	if keepalive <= 0 {
		keepalive = 10 * time.Second
	}
	ln, err := quic.ListenAddr(addr, conf, quicConfig(keepalive))
	if err != nil {
		return nil, err
	}
	return &QUICListener{ln: ln}, nil
}

func (l *QUICListener) Name() string   { return "quic" }
func (l *QUICListener) Addr() net.Addr { return l.ln.Addr() }
func (l *QUICListener) Close() error   { return l.ln.Close() }

func (l *QUICListener) Accept(ctx context.Context) (Carrier, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &quicCarrier{conn: conn}, nil
}

// quicCarrier maps the Carrier contract onto a QUIC connection.
type quicCarrier struct {
	conn quic.Connection
}

func (q *quicCarrier) OpenStream(ctx context.Context) (Stream, error) {
	s, err := q.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (q *quicCarrier) AcceptStream(ctx context.Context) (Stream, error) {
	s, err := q.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (q *quicCarrier) SendDatagram(b []byte) error      { return q.conn.SendDatagram(b) }
func (q *quicCarrier) MaxDatagramSize() int             { return quicMaxDatagram }
func (q *quicCarrier) LocalAddr() net.Addr              { return q.conn.LocalAddr() }
func (q *quicCarrier) RemoteAddr() net.Addr             { return q.conn.RemoteAddr() }
func (q *quicCarrier) Done() <-chan struct{}            { return q.conn.Context().Done() }
func (q *quicCarrier) Transport() string                { return "quic" }

func (q *quicCarrier) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return q.conn.ReceiveDatagram(ctx)
}

func (q *quicCarrier) Close() error {
	return q.conn.CloseWithError(0, "")
}

func cloneTLS(c *tls.Config) *tls.Config {
	if c == nil {
		return &tls.Config{MinVersion: tls.VersionTLS13}
	}
	out := c.Clone()
	if out.MinVersion < tls.VersionTLS12 {
		out.MinVersion = tls.VersionTLS13
	}
	return out
}
