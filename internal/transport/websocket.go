package transport

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"

)

// WSDialer dials the relay as a WebSocket over TLS. This is the stealth path
// and the recommended default for a link crossing an inspected border.
//
// What a DPI box sees, end to end:
//
//	a Chrome ClientHello (uTLS)            -> JA3/JA4 of a real browser
//	SNI of a real domain with a real cert  -> no self-signed red flag
//	ALPN h2/http1.1                        -> ordinary web traffic
//	GET /<secret path> + Upgrade           -> a web app with a websocket
//	records of randomised size (obfs)      -> no tunnel-shaped flow
//	and probing "/" returns a real site    -> active probe finds a website
//
// No CDN is required for any of that. A CDN only adds a second, slower path
// for when the direct address is blocked outright.
type WSDialer struct {
	// URL is the full wss:// endpoint. Use a non-obvious path: the default
	// /ws is fine behind a CDN but a distinctive path is one more thing a
	// prober has to guess.
	URL string
	// EdgeAddr optionally forces the TCP destination while SNI and Host keep
	// the names in URL. Set it to a CDN edge address, or to the relay's raw IP
	// when DNS is unreliable.
	EdgeAddr string
	// Host overrides the HTTP Host header.
	Host string
	// Fingerprint selects the ClientHello to imitate; "chrome" is the default
	// applied by the config layer.
	Fingerprint Fingerprint
	// RootCAs pins acceptable issuers; nil uses the system pool.
	RootCAs *x509.CertPool
	// PinnedSPKI pins the relay's public key.
	PinnedSPKI []string
	// Insecure disables certificate verification; requires PinnedSPKI.
	Insecure bool
	// Headers are extra request headers. Use them to look like a specific web
	// app rather than a bare websocket client.
	Headers http.Header
	// Mux tunes the multiplexer: shaping, stream window and stream cap.
	Mux MuxOptions
	// DialTimeout bounds the whole upgrade.
	DialTimeout time.Duration
}

func (d *WSDialer) Name() string { return "websocket" }

func (d *WSDialer) Dial(ctx context.Context) (Carrier, error) {
	timeout := d.DialTimeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u, err := url.Parse(d.URL)
	if err != nil {
		return nil, err
	}
	sni := u.Hostname()
	if d.Host != "" {
		if h, _, err := net.SplitHostPort(d.Host); err == nil {
			sni = h
		} else {
			sni = d.Host
		}
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "ws" {
			port = "80"
		} else {
			port = "443"
		}
	}
	target := net.JoinHostPort(u.Hostname(), port)
	if d.EdgeAddr != "" {
		target = d.EdgeAddr
	}

	base := &net.Dialer{KeepAlive: 15 * time.Second}
	params := tlsParams{
		ServerName:         sni,
		RootCAs:            d.RootCAs,
		InsecureSkipVerify: d.Insecure,
		PinnedSPKI:         d.PinnedSPKI,
		// A browser offers exactly this. Anything else undoes the mimicry.
		NextProtos: browserALPN,
	}

	fp := d.Fingerprint
	if fp == FingerprintNone {
		fp = FingerprintChrome
	}

	transport := &http.Transport{
		// ForceAttemptHTTP2 stays off: the upgrade needs a hijackable
		// HTTP/1.1 connection, and the relay answers http/1.1 for /ws.
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		ResponseHeaderTimeout: timeout,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, alpn, err := dialMimic(ctx, base, target, fp, params)
			if err != nil {
				return nil, err
			}
			if alpn == "h2" {
				conn.Close()
				return nil, fmt.Errorf("transport: relay chose h2; the websocket path needs http/1.1")
			}
			return conn, nil
		},
	}

	hdr := http.Header{}
	for k, vs := range d.Headers {
		for _, v := range vs {
			hdr.Add(k, v)
		}
	}

	ws, _, err := websocket.Dial(dialCtx, u.String(), &websocket.DialOptions{
		HTTPClient:      &http.Client{Transport: transport},
		HTTPHeader:      hdr,
		Host:            d.Host,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(1 << 22)

	// The carrier outlives the dial, so it gets a background context.
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	return NewMuxCarrier("websocket", conn, true, d.Mux)
}

// AcceptWebSocket adapts an accepted server-side WebSocket into a Carrier.
func AcceptWebSocket(ws *websocket.Conn, opts MuxOptions) (Carrier, error) {
	ws.SetReadLimit(1 << 22)
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	return NewMuxCarrier("websocket", conn, false, opts)
}
