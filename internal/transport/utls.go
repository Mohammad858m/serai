package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Fingerprint names the ClientHello a dialer should imitate.
//
// This matters more than any other anti-detection measure in this project.
// Go's crypto/tls emits a ClientHello that no browser produces: a distinctive
// cipher order, no GREASE values, no ALPS, no compressed-certificate
// extension. A DPI box computes JA3/JA4 over those bytes, sees "Go client on
// port 443 to a VPS", and that single observation is enough to flag the relay
// without ever decrypting a byte. Every tunnel built on plain crypto/tls --
// frp, chisel, rathole and most of their forks -- carries that tell.
//
// Only the _Auto profiles are used so a utls upgrade keeps working.
type Fingerprint string

const (
	FingerprintNone     Fingerprint = ""        // plain crypto/tls; fast, but fingerprintable
	FingerprintChrome   Fingerprint = "chrome"  // the safest default
	FingerprintFirefox  Fingerprint = "firefox"
	FingerprintEdge     Fingerprint = "edge"
	FingerprintSafari   Fingerprint = "safari"
	FingerprintIOS      Fingerprint = "ios"
	FingerprintAndroid  Fingerprint = "android"
	FingerprintRandom   Fingerprint = "random"
)

// browserALPN is what a real browser offers. Advertising a custom ALPN next to
// a Chrome ClientHello would defeat the whole exercise, so a mimicked dial
// always claims to be ordinary web traffic and carries the tunnel over
// WebSocket instead.
var browserALPN = []string{"h2", "http/1.1"}

func (f Fingerprint) helloID() (utls.ClientHelloID, error) {
	switch Fingerprint(strings.ToLower(string(f))) {
	case FingerprintChrome:
		return utls.HelloChrome_Auto, nil
	case FingerprintFirefox:
		return utls.HelloFirefox_Auto, nil
	case FingerprintEdge:
		return utls.HelloEdge_Auto, nil
	case FingerprintSafari:
		return utls.HelloSafari_Auto, nil
	case FingerprintIOS:
		return utls.HelloIOS_Auto, nil
	case FingerprintAndroid:
		return utls.HelloAndroid_11_OkHttp, nil
	case FingerprintRandom:
		return utls.HelloRandomizedALPN, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("transport: unknown TLS fingerprint %q", string(f))
	}
}

// Valid reports whether f names a supported profile.
func (f Fingerprint) Valid() bool {
	if f == FingerprintNone {
		return true
	}
	_, err := f.helloID()
	return err == nil
}

// tlsParams is the subset of TLS settings this package needs, kept separate
// from *tls.Config because utls defines its own Config type.
type tlsParams struct {
	ServerName         string
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool
	// PinnedSPKI, when non-empty, requires the leaf certificate's public key
	// to hash to one of these values. It lets a relay run a self-signed cert
	// safely -- but see the docs: a real domain with a real certificate is the
	// stealthier choice, because a self-signed cert on 443 is itself a signal.
	PinnedSPKI []string
	NextProtos []string
}

// dialMimic opens a TCP connection and completes a TLS handshake whose
// ClientHello imitates fp. The returned conn is a net.Conn carrying TLS.
func dialMimic(ctx context.Context, dialer *net.Dialer, addr string, fp Fingerprint, p tlsParams) (net.Conn, string, error) {
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	if fp == FingerprintNone {
		conf := &tls.Config{
			ServerName:         p.ServerName,
			RootCAs:            p.RootCAs,
			InsecureSkipVerify: p.InsecureSkipVerify || len(p.PinnedSPKI) > 0,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         p.NextProtos,
		}
		if len(p.PinnedSPKI) > 0 {
			conf.VerifyPeerCertificate = pinVerifier(p.PinnedSPKI)
		}
		c := tls.Client(raw, conf)
		if err := c.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, "", err
		}
		return c, c.ConnectionState().NegotiatedProtocol, nil
	}

	id, err := fp.helloID()
	if err != nil {
		raw.Close()
		return nil, "", err
	}

	alpn := p.NextProtos
	if len(alpn) == 0 {
		alpn = browserALPN
	}
	conf := &utls.Config{
		ServerName:         p.ServerName,
		RootCAs:            p.RootCAs,
		InsecureSkipVerify: p.InsecureSkipVerify || len(p.PinnedSPKI) > 0,
		MinVersion:         utls.VersionTLS12,
		NextProtos:         alpn,
	}
	if len(p.PinnedSPKI) > 0 {
		conf.VerifyPeerCertificate = pinVerifier(p.PinnedSPKI)
	}

	c := utls.UClient(raw, conf, id)
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, "", err
	}
	return c, c.ConnectionState().NegotiatedProtocol, nil
}

// pinVerifier builds a VerifyPeerCertificate callback. crypto/tls and utls
// declare the same signature for it, so one function serves both.
func pinVerifier(pins []string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return checkPins(rawCerts, pins)
	}
}
