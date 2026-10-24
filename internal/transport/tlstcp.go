package transport

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"

)

// TLSDialer dials the relay over TCP+TLS and selects the mtunnel ALPN
// directly, skipping the HTTP layer.
//
// This is the fastest path and the right default on a link that is not under
// inspection -- a private backbone, a second provider, a tunnel between two
// hosts abroad. Under active DPI prefer WSDialer: a custom ALPN cannot be
// disguised, because a Chrome-shaped ClientHello that advertises "mtnl/1" is a
// stronger signal than a plain Go one. The honest trade is throughput versus
// stealth, and the config makes you choose rather than guessing for you.
type TLSDialer struct {
	// Addr is host:port of the relay.
	Addr string
	// ServerName is the SNI and the name verified on the certificate.
	ServerName string
	// Fingerprint mimics a browser ClientHello. Leave empty here; see above.
	Fingerprint Fingerprint
	// RootCAs pins acceptable issuers; nil uses the system pool.
	RootCAs *x509.CertPool
	// PinnedSPKI pins the relay's public key, which is what makes a private CA
	// or a self-signed certificate safe to use.
	PinnedSPKI []string
	// Insecure disables certificate verification entirely. Only acceptable
	// together with PinnedSPKI, and the config layer enforces that.
	Insecure bool
	// Mux tunes the multiplexer: shaping, stream window and stream cap.
	Mux MuxOptions
	// DialTimeout bounds the TCP connect and the TLS handshake together.
	DialTimeout time.Duration
}

func (d *TLSDialer) Name() string { return "tls" }

func (d *TLSDialer) Dial(ctx context.Context) (Carrier, error) {
	timeout := d.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sni := d.ServerName
	if sni == "" {
		host, _, err := net.SplitHostPort(d.Addr)
		if err != nil {
			return nil, err
		}
		sni = host
	}

	conn, alpn, err := dialMimic(ctx, &net.Dialer{KeepAlive: 15 * time.Second}, d.Addr, d.Fingerprint, tlsParams{
		ServerName:         sni,
		RootCAs:            d.RootCAs,
		InsecureSkipVerify: d.Insecure,
		PinnedSPKI:         d.PinnedSPKI,
		NextProtos:         []string{ALPN},
	})
	if err != nil {
		return nil, err
	}
	if alpn != ALPN {
		conn.Close()
		return nil, fmt.Errorf("transport: relay negotiated %q instead of %q", alpn, ALPN)
	}

	return NewMuxCarrier("tls", conn, true, d.Mux)
}
