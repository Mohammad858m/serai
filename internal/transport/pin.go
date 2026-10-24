package transport

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ErrPinMismatch means the server's key did not match any configured pin.
var ErrPinMismatch = errors.New("transport: certificate pin mismatch")

// SPKIPin returns the base64 SHA-256 of a certificate's SubjectPublicKeyInfo,
// the same value as:
//
//	openssl x509 -in cert.pem -pubkey -noout |
//	  openssl pkey -pubin -outform der |
//	  openssl dgst -sha256 -binary | base64
//
// Pinning the key rather than the certificate means a renewal that keeps the
// key pair does not invalidate the pin.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// checkPins verifies the leaf certificate against a list of SPKI pins.
// Accepts base64 (openssl style) and hex, with an optional "sha256/" prefix.
func checkPins(rawCerts [][]byte, pins []string) error {
	if len(rawCerts) == 0 {
		return errors.New("transport: server presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("transport: parse leaf certificate: %w", err)
	}

	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	gotB64 := base64.StdEncoding.EncodeToString(sum[:])
	gotHex := hex.EncodeToString(sum[:])

	for _, p := range pins {
		p = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(p), "sha256/"))
		if p == "" {
			continue
		}
		if p == gotB64 || strings.EqualFold(p, gotHex) {
			return nil
		}
	}
	return fmt.Errorf("%w (server key is sha256/%s)", ErrPinMismatch, gotB64)
}
