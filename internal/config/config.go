// Package config loads and validates Serai's configuration.
//
// One file describes both roles. The origin (abroad, next to the panel) owns
// the forwarding rules; the edge (the relay users dial) needs only a key, a
// certificate and a port. That split is deliberate: everything you tune while
// adding an inbound to 3x-ui lives on the host where 3x-ui already runs.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Mohammad858m/serai/internal/obfs"
	"github.com/Mohammad858m/serai/internal/protocol"
	"github.com/Mohammad858m/serai/internal/transport"
)

// Role is which half of the tunnel this process runs.
type Role string

const (
	// RoleEdge is the relay: it listens, and users connect to it.
	RoleEdge Role = "edge"
	// RoleOrigin is the host that owns the panel: it dials the edge.
	RoleOrigin Role = "origin"
)

// Profile presets the speed/stealth trade-off, which is real and cannot be
// optimised away. Each preset is applied before per-field overrides, so you
// can start from a profile and adjust one knob.
type Profile string

const (
	// ProfileSpeed is the lowest latency and highest throughput: QUIC and
	// direct ALPN, no shaping. Appropriate when the path is not inspected.
	ProfileSpeed Profile = "speed"
	// ProfileBalanced shapes the control channel only and prefers QUIC with a
	// browser-mimicking WebSocket fallback. The default.
	ProfileBalanced Profile = "balanced"
	// ProfileStealth shapes everything and uses only the WebSocket path, at a
	// cost of roughly 5-10% bandwidth and some CPU.
	ProfileStealth Profile = "stealth"
)

// ObfsScope selects which carriers get traffic shaping.
type ObfsScope string

const (
	ObfsNone    ObfsScope = "none"
	ObfsControl ObfsScope = "control"
	ObfsAll     ObfsScope = "all"
)

// Config is the whole file.
type Config struct {
	Role     Role    `json:"role"`
	Name     string  `json:"name"`
	LogLevel string  `json:"log_level"`
	Profile  Profile `json:"profile"`

	// PSK is the shared secret, base64 or "hex:..."; PSKFile reads it from disk
	// so it never appears in a config you might paste into a chat.
	PSK     string `json:"psk"`
	PSKFile string `json:"psk_file"`

	// Origin side.
	Edge     *EdgeClient        `json:"edge,omitempty"`
	Forwards []protocol.Forward `json:"forwards,omitempty"`

	// Edge side.
	Server *EdgeServer `json:"server,omitempty"`

	Tuning Tuning     `json:"tuning"`
	Obfs   ObfsConfig `json:"obfs"`

	// AdminAddr serves metrics and status on localhost. Never bind it publicly.
	AdminAddr string `json:"admin_addr"`

	psk []byte
}

// ObfsConfig controls the traffic-shaping layer.
type ObfsConfig struct {
	Scope ObfsScope `json:"scope"`
	// MinChunk/MaxChunk/MinPad/MaxPad/CoverInterval mirror obfs.Config. Larger
	// chunks cost less CPU and throughput; smaller ones hide more.
	MinChunk      int    `json:"min_chunk"`
	MaxChunk      int    `json:"max_chunk"`
	MinPad        int    `json:"min_pad"`
	MaxPad        int    `json:"max_pad"`
	CoverInterval string `json:"cover_interval"`
	CoverJitter   float64 `json:"cover_jitter"`
}

// Tuning holds the knobs that decide throughput on a high-latency link.
type Tuning struct {
	// StreamWindow is the per-stream receive window in bytes.
	//
	// It is a memory ceiling as much as a speed knob: the worst case this
	// process can be made to hold is roughly
	//
	//	stream_window x max_streams x carriers
	//
	// so 16 MiB x 256 x 3 would be twelve gigabytes. VPN traffic is many
	// concurrent small flows, where aggregate throughput comes from
	// concurrency and from running several carriers, not from a large window.
	// Stay in the 1-4 MiB range unless the workload really is a handful of
	// very fat flows and the host has the RAM for it.
	StreamWindow int `json:"stream_window"`
	// MaxStreams caps concurrent streams per carrier, bounding both memory and
	// the damage a flood can do.
	MaxStreams int `json:"max_streams"`
	// CopyBuffer is the relay copy buffer; 64 KiB keeps syscall count low.
	CopyBuffer int `json:"copy_buffer"`
	// Carriers is how many independent connections make up the tunnel. More
	// than one removes head-of-line blocking and sidesteps per-flow shaping.
	Carriers int `json:"carriers"`

	// Keepalive is the control-stream ping interval.
	Keepalive string `json:"keepalive"`
	// DialTimeout bounds one dial attempt.
	DialTimeout string `json:"dial_timeout"`
}

// Path is one candidate route to the edge.
type Path struct {
	// Transport is "quic", "tls" or "websocket".
	Transport string `json:"transport"`
	// Addr is host:port for quic and tls.
	Addr string `json:"addr,omitempty"`
	// URL is the wss:// endpoint for websocket.
	URL string `json:"url,omitempty"`
	// EdgeAddr forces the TCP/UDP destination while names stay as configured;
	// set it to a CDN edge or to a raw IP.
	EdgeAddr string `json:"edge_addr,omitempty"`
	// Host overrides SNI and the HTTP Host header.
	Host string `json:"host,omitempty"`
	// Fingerprint is the ClientHello to imitate: chrome, firefox, edge,
	// safari, ios, android, random, or "" for Go's own (fingerprintable).
	Fingerprint string `json:"fingerprint,omitempty"`
	// Role is "both", "data" or "bootstrap". A CDN-fronted path set to
	// "bootstrap" keeps the tunnel registered for pennies while bulk traffic
	// takes a direct path at full speed.
	Role string `json:"role,omitempty"`
	// Weight biases how many carriers this path gets; higher wins more.
	Weight int `json:"weight,omitempty"`
	// Headers are extra HTTP headers for the websocket path.
	Headers map[string]string `json:"headers,omitempty"`
}

// EdgeClient is the origin's view of the relay.
type EdgeClient struct {
	Paths      []Path   `json:"paths"`
	PinnedSPKI []string `json:"pinned_spki,omitempty"`
	// Insecure skips certificate verification; only allowed with PinnedSPKI.
	Insecure bool `json:"insecure,omitempty"`
	// CAFile adds a private CA.
	CAFile string `json:"ca_file,omitempty"`
	// Reconnect shapes the backoff after a failure.
	Reconnect Backoff `json:"reconnect"`
}

// Backoff is exponential backoff with jitter. The jitter is not cosmetic: a
// fleet of relays reconnecting on a fixed 1-second timer after a cut is itself
// a detectable pattern, and a sharp retry loop is what turns a transient
// filter into a permanent one.
type Backoff struct {
	Min    string  `json:"min"`
	Max    string  `json:"max"`
	Factor float64 `json:"factor"`
	Jitter float64 `json:"jitter"`
}

// EdgeServer is the relay's own configuration.
type EdgeServer struct {
	// ControlAddr is the single TCP port to expose, normally ":443".
	ControlAddr string `json:"control_addr"`
	// QUICAddr is the UDP port, normally the same ":443". Empty disables QUIC.
	QUICAddr string `json:"quic_addr"`
	// TunnelSNI is the hostname that reaches Serai itself. Any other SNI is
	// either forwarded to a backend or sent to the decoy.
	TunnelSNI string `json:"tunnel_sni"`
	// WSPath is the WebSocket endpoint. Pick something unremarkable that fits
	// the decoy site; the default is deliberately bland.
	WSPath string `json:"ws_path"`
	// CertFile and KeyFile are the certificate for TunnelSNI. Use a real
	// certificate for a real domain: a self-signed cert on 443 is a signal all
	// by itself, regardless of how good the rest of the camouflage is.
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	// DecoyUpstream is reverse-proxied for every request that is not the
	// tunnel, so an active probe finds a working website.
	DecoyUpstream string `json:"decoy_upstream"`
	// AllowPorts limits which edge ports an authenticated origin may claim.
	AllowPorts string `json:"allow_ports"`
	// MaxSessions caps concurrent origins.
	MaxSessions int `json:"max_sessions"`
}

var commentRE = regexp.MustCompile(`(?m)^\s*//.*$`)

// Load reads, de-comments, parses and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Allow // line comments so a deployed config can document itself.
	clean := commentRE.ReplaceAll(raw, []byte(""))

	var c Config
	dec := json.NewDecoder(strings.NewReader(string(clean)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	if err := c.finalize(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}

// PSKBytes returns the decoded pre-shared key.
func (c *Config) PSKBytes() []byte { return c.psk }

func (c *Config) finalize() error {
	if c.Profile == "" {
		c.Profile = ProfileBalanced
	}
	c.applyProfile()

	if c.Name == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = string(c.Role)
		}
		c.Name = host
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.AdminAddr == "" {
		c.AdminAddr = "127.0.0.1:9900"
	}

	if err := c.loadPSK(); err != nil {
		return err
	}

	switch c.Role {
	case RoleEdge:
		return c.finalizeEdge()
	case RoleOrigin:
		return c.finalizeOrigin()
	default:
		return fmt.Errorf("role must be %q or %q", RoleEdge, RoleOrigin)
	}
}

// applyProfile fills unset fields from the chosen profile. Explicit values in
// the file always win, so a profile is a starting point rather than a cage.
func (c *Config) applyProfile() {
	switch c.Profile {
	case ProfileSpeed:
		setDefaultStr((*string)(&c.Obfs.Scope), string(ObfsNone))
		setDefaultInt(&c.Tuning.Carriers, 4)
		setDefaultInt(&c.Tuning.StreamWindow, 4<<20)
	case ProfileStealth:
		setDefaultStr((*string)(&c.Obfs.Scope), string(ObfsAll))
		setDefaultInt(&c.Tuning.Carriers, 2)
		setDefaultInt(&c.Tuning.StreamWindow, 1<<20)
	default: // balanced
		c.Profile = ProfileBalanced
		setDefaultStr((*string)(&c.Obfs.Scope), string(ObfsControl))
		setDefaultInt(&c.Tuning.Carriers, 3)
		setDefaultInt(&c.Tuning.StreamWindow, 2<<20)
	}
	setDefaultInt(&c.Tuning.MaxStreams, 256)
	setDefaultInt(&c.Tuning.CopyBuffer, 32<<10)
	setDefaultStr(&c.Tuning.Keepalive, "10s")
	setDefaultStr(&c.Tuning.DialTimeout, "12s")
}

func setDefaultInt(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

func setDefaultStr(p *string, v string) {
	if *p == "" {
		*p = v
	}
}

func (c *Config) loadPSK() error {
	src := c.PSK
	if c.PSKFile != "" {
		b, err := os.ReadFile(c.PSKFile)
		if err != nil {
			return fmt.Errorf("psk_file: %w", err)
		}
		src = strings.TrimSpace(string(b))
	}
	if src == "" {
		return errors.New("psk or psk_file is required")
	}

	var (
		key []byte
		err error
	)
	if rest, ok := strings.CutPrefix(src, "hex:"); ok {
		key, err = decodeHex(rest)
	} else {
		key, err = base64.StdEncoding.DecodeString(src)
		if err != nil {
			key, err = base64.RawURLEncoding.DecodeString(src)
		}
	}
	if err != nil {
		return fmt.Errorf("psk: not valid base64 or hex: %w", err)
	}
	if len(key) < 16 {
		return fmt.Errorf("psk: need at least 16 bytes of key material, got %d", len(key))
	}
	c.psk = key
	return nil
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

func (c *Config) finalizeEdge() error {
	if c.Server == nil {
		return errors.New("edge role requires a \"server\" block")
	}
	s := c.Server
	setDefaultStr(&s.ControlAddr, ":443")
	setDefaultStr(&s.WSPath, "/ws")
	if !strings.HasPrefix(s.WSPath, "/") {
		s.WSPath = "/" + s.WSPath
	}
	if s.MaxSessions == 0 {
		s.MaxSessions = 8
	}
	if s.CertFile == "" || s.KeyFile == "" {
		return errors.New("server.cert_file and server.key_file are required")
	}
	if s.TunnelSNI == "" {
		return errors.New("server.tunnel_sni is required so user traffic and tunnel traffic can share port 443")
	}
	if s.AllowPorts != "" {
		if _, err := ParsePorts(s.AllowPorts); err != nil {
			return fmt.Errorf("server.allow_ports: %w", err)
		}
	}
	if len(c.Forwards) > 0 {
		return errors.New("forwards belong in the origin config; the edge learns them at registration")
	}
	return nil
}

func (c *Config) finalizeOrigin() error {
	if c.Edge == nil || len(c.Edge.Paths) == 0 {
		return errors.New("origin role requires \"edge.paths\" with at least one path")
	}
	if c.Edge.Insecure && len(c.Edge.PinnedSPKI) == 0 {
		return errors.New("edge.insecure requires edge.pinned_spki; disabling verification without a pin accepts any MITM")
	}

	b := &c.Edge.Reconnect
	setDefaultStr(&b.Min, "1s")
	setDefaultStr(&b.Max, "120s")
	if b.Factor == 0 {
		b.Factor = 1.8
	}
	if b.Jitter == 0 {
		b.Jitter = 0.3
	}

	for i := range c.Edge.Paths {
		p := &c.Edge.Paths[i]
		switch p.Transport {
		case "quic", "tls":
			if p.Addr == "" {
				return fmt.Errorf("edge.paths[%d]: %s needs \"addr\"", i, p.Transport)
			}
		case "websocket":
			if p.URL == "" {
				return fmt.Errorf("edge.paths[%d]: websocket needs \"url\"", i)
			}
		default:
			return fmt.Errorf("edge.paths[%d]: transport must be quic, tls or websocket", i)
		}
		if p.Weight <= 0 {
			p.Weight = 1
		}
		if p.Role == "" {
			p.Role = string(transport.RoleBoth)
		}
		switch transport.Role(p.Role) {
		case transport.RoleBoth, transport.RoleData, transport.RoleBootstrap:
		default:
			return fmt.Errorf("edge.paths[%d]: role must be both, data or bootstrap", i)
		}
		if p.Transport == "websocket" && p.Fingerprint == "" {
			// A browser fingerprint is the whole point of the websocket path.
			p.Fingerprint = string(transport.FingerprintChrome)
		}
		if !transport.Fingerprint(p.Fingerprint).Valid() {
			return fmt.Errorf("edge.paths[%d]: unknown fingerprint %q", i, p.Fingerprint)
		}
	}

	if len(c.Forwards) == 0 {
		return errors.New("origin role requires at least one entry in \"forwards\"")
	}
	seen := map[string]bool{}
	for i := range c.Forwards {
		f := &c.Forwards[i]
		if f.Name == "" {
			return fmt.Errorf("forwards[%d]: name is required", i)
		}
		if seen[f.Name] {
			return fmt.Errorf("forwards[%d]: duplicate name %q", i, f.Name)
		}
		seen[f.Name] = true

		if f.Proto == "" {
			f.Proto = "tcp"
		}
		switch f.Proto {
		case "tcp", "udp", "tcp+udp":
		default:
			return fmt.Errorf("forwards[%d]: proto must be tcp, udp or tcp+udp", i)
		}
		if f.ProxyProtocol != 0 && f.ProxyProtocol != 1 && f.ProxyProtocol != 2 {
			return fmt.Errorf("forwards[%d]: proxy_protocol must be 0, 1 or 2", i)
		}
		if f.ProxyProtocol == 1 && f.WantsUDP() {
			return fmt.Errorf("forwards[%d]: PROXY protocol v1 cannot describe UDP; use 2", i)
		}

		ports, err := ParsePorts(f.EdgePorts)
		if err != nil {
			return fmt.Errorf("forwards[%d] (%s): edge_ports: %w", i, f.Name, err)
		}
		if len(ports) == 0 && len(f.SNI) == 0 {
			return fmt.Errorf("forwards[%d] (%s): needs edge_ports, sni, or both", i, f.Name)
		}
		f.Ports = ports

		if f.Target == "" && f.TargetHost == "" {
			return fmt.Errorf("forwards[%d] (%s): needs target or target_host", i, f.Name)
		}
		if f.Target != "" && len(ports) > 1 {
			return fmt.Errorf("forwards[%d] (%s): a fixed target cannot serve %d ports; use target_host to keep the port", i, f.Name, len(ports))
		}
	}
	return nil
}

// MemoryCeiling reports the worst-case buffered bytes implied by the tuning,
// so an operator can sanity-check it against the host before deploying.
func (c *Config) MemoryCeiling() int64 {
	return int64(c.Tuning.StreamWindow) * int64(c.Tuning.MaxStreams) * int64(c.Tuning.Carriers)
}

// MuxOptions renders the tuning for a carrier of the given role.
func (c *Config) MuxOptions(role transport.Role) transport.MuxOptions {
	return transport.MuxOptions{
		Obfs:         c.ObfsFor(role),
		StreamWindow: c.Tuning.StreamWindow,
		MaxStreams:   c.Tuning.MaxStreams,
	}
}

// ObfsFor returns the shaping config for a carrier role, or nil for none.
func (c *Config) ObfsFor(role transport.Role) *obfs.Config {
	switch ObfsScope(c.Obfs.Scope) {
	case ObfsNone:
		return nil
	case ObfsControl:
		if role == transport.RoleData {
			return nil
		}
	}
	cfg := obfs.Defaults()
	if c.Obfs.MinChunk > 0 {
		cfg.MinChunk = c.Obfs.MinChunk
	}
	if c.Obfs.MaxChunk > 0 {
		cfg.MaxChunk = c.Obfs.MaxChunk
	}
	if c.Obfs.MinPad > 0 {
		cfg.MinPad = c.Obfs.MinPad
	}
	if c.Obfs.MaxPad > 0 {
		cfg.MaxPad = c.Obfs.MaxPad
	}
	if c.Obfs.CoverJitter > 0 {
		cfg.CoverJitter = c.Obfs.CoverJitter
	}
	if d, err := time.ParseDuration(c.Obfs.CoverInterval); err == nil && d >= 0 {
		cfg.CoverInterval = d
	}
	return &cfg
}

// Duration parses one of the duration-shaped string fields.
func Duration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// ParsePorts and PortAllowed delegate to the protocol package, which owns them
// because both halves of the tunnel expand the same spec independently.
func ParsePorts(spec string) ([]int, error) { return protocol.ParsePorts(spec) }

// PortAllowed reports whether p is within spec. An empty spec allows all.
func PortAllowed(spec string, p int) bool { return protocol.PortAllowed(spec, p) }
