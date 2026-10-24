// Package proxyproto writes HAProxy PROXY protocol headers.
//
// Without this, every connection the origin hands to Xray/3x-ui appears to
// come from 127.0.0.1, which breaks per-IP limits, GeoIP routing and the
// panel's client list. With it, the panel sees the user's real address. Xray
// accepts both versions when an inbound sets "acceptProxyProtocol": true.
package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

var sigV2 = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ErrUnsupported is returned for an address pair that cannot be encoded, for
// example a mix of IPv4 and IPv6.
var ErrUnsupported = errors.New("proxyproto: unsupported address pair")

// Write emits a header of the given version (1 or 2) describing a connection
// from src to dst. Version 0 writes nothing.
func Write(w io.Writer, version int, src, dst netip.AddrPort, udp bool) error {
	switch version {
	case 0:
		return nil
	case 1:
		return writeV1(w, src, dst, udp)
	case 2:
		return writeV2(w, src, dst, udp)
	default:
		return fmt.Errorf("proxyproto: unknown version %d", version)
	}
}

func writeV1(w io.Writer, src, dst netip.AddrPort, udp bool) error {
	if udp {
		// v1 has no UDP encoding; callers that need UDP must use v2.
		return ErrUnsupported
	}
	var family string
	switch {
	case src.Addr().Is4() && dst.Addr().Is4():
		family = "TCP4"
	case src.Addr().Is6() && dst.Addr().Is6():
		family = "TCP6"
	default:
		return ErrUnsupported
	}
	line := fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
		family, src.Addr().String(), dst.Addr().String(), src.Port(), dst.Port())
	_, err := io.WriteString(w, line)
	return err
}

func writeV2(w io.Writer, src, dst netip.AddrPort, udp bool) error {
	var (
		fam      byte
		addrSize int
	)
	switch {
	case src.Addr().Is4() && dst.Addr().Is4():
		fam, addrSize = 0x10, 4 // AF_INET
	case src.Addr().Is6() && dst.Addr().Is6():
		fam, addrSize = 0x20, 16 // AF_INET6
	default:
		return ErrUnsupported
	}
	if udp {
		fam |= 0x02 // DGRAM
	} else {
		fam |= 0x01 // STREAM
	}

	body := make([]byte, 0, 2*addrSize+4)
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	s16, d16 := src.Addr().As16(), dst.Addr().As16()
	if addrSize == 4 {
		body = append(body, s4[:]...)
		body = append(body, d4[:]...)
	} else {
		body = append(body, s16[:]...)
		body = append(body, d16[:]...)
	}
	body = binary.BigEndian.AppendUint16(body, src.Port())
	body = binary.BigEndian.AppendUint16(body, dst.Port())

	hdr := make([]byte, 0, len(sigV2)+4+len(body))
	hdr = append(hdr, sigV2...)
	hdr = append(hdr, 0x21, fam) // version 2 + PROXY command
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(body)))
	hdr = append(hdr, body...)

	_, err := w.Write(hdr)
	return err
}

// ParseAddrPort converts a net.Addr or "host:port" string into netip.AddrPort,
// unmapping IPv4-in-IPv6 so the encoded family matches what the peer expects.
func ParseAddrPort(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		// Fall back to a resolve for names and for "0.0.0.0:0"-style inputs.
		host, port, serr := net.SplitHostPort(s)
		if serr != nil {
			return netip.AddrPort{}, err
		}
		ip, ierr := netip.ParseAddr(host)
		if ierr != nil {
			return netip.AddrPort{}, err
		}
		var p uint16
		if _, serr := fmt.Sscanf(port, "%d", &p); serr != nil {
			return netip.AddrPort{}, err
		}
		ap = netip.AddrPortFrom(ip, p)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
