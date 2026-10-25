package relay

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/Mohammad858m/serai/internal/auth"
	"github.com/Mohammad858m/serai/internal/config"
	"github.com/Mohammad858m/serai/internal/pool"
	"github.com/Mohammad858m/serai/internal/protocol"
	"github.com/Mohammad858m/serai/internal/proxyproto"
	"github.com/Mohammad858m/serai/internal/transport"
	"github.com/Mohammad858m/serai/internal/wire"
)

// Origin is the half that owns the panel. It dials the relay, declares which
// ports the relay should open, and connects each forwarded stream to a local
// backend.
//
// Dialling outward is the whole reason this shape works: the relay never has
// to open a connection to a filtered address, and this host needs no inbound
// firewall rule, no public port and no certificate of its own.
type Origin struct {
	cfg  *config.Config
	log  *slog.Logger
	cred auth.Credentials
	set  *pool.Set

	forwards map[string]protocol.Forward
	cands    []*candidate

	mu    sync.Mutex
	token string
	rnd   *rand.Rand
}

// candidate is one configured path plus its failure state.
type candidate struct {
	name   string
	dialer transport.Dialer
	role   transport.Role
	weight int

	fails   int
	nextTry time.Time
}

// NewOrigin builds an origin from a validated config.
func NewOrigin(cfg *config.Config, log *slog.Logger) (*Origin, error) {
	o := &Origin{
		cfg:      cfg,
		log:      log,
		cred:     auth.NewCredentials(cfg.PSKBytes()),
		set:      pool.NewSet(),
		forwards: make(map[string]protocol.Forward, len(cfg.Forwards)),
		rnd:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	for _, f := range cfg.Forwards {
		o.forwards[f.Name] = f
	}
	if err := o.buildCandidates(); err != nil {
		return nil, err
	}
	return o, nil
}

// Set exposes the carrier set for the status endpoint.
func (o *Origin) Set() *pool.Set { return o.set }

func (o *Origin) buildCandidates() error {
	var roots *x509.CertPool
	if f := o.cfg.Edge.CAFile; f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("edge.ca_file: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("edge.ca_file: no certificates found in %s", f)
		}
	}

	timeout := config.Duration(o.cfg.Tuning.DialTimeout, 12*time.Second)

	for i := range o.cfg.Edge.Paths {
		p := o.cfg.Edge.Paths[i]
		role := transport.Role(p.Role)
		mux := o.cfg.MuxOptions(role)

		var d transport.Dialer
		switch p.Transport {
		case "quic":
			addr := p.Addr
			if p.EdgeAddr != "" {
				addr = p.EdgeAddr
			}
			sni := p.Host
			if sni == "" {
				if h, _, err := net.SplitHostPort(p.Addr); err == nil {
					sni = h
				}
			}
			d = &transport.QUICDialer{
				Addr:       addr,
				ServerName: sni,
				RootCAs:    roots,
				PinnedSPKI: o.cfg.Edge.PinnedSPKI,
				Insecure:   o.cfg.Edge.Insecure,
				Keepalive:  config.Duration(o.cfg.Tuning.Keepalive, 10*time.Second),
			}
		case "tls":
			d = &transport.TLSDialer{
				Addr:        p.Addr,
				ServerName:  p.Host,
				Fingerprint: transport.Fingerprint(p.Fingerprint),
				RootCAs:     roots,
				PinnedSPKI:  o.cfg.Edge.PinnedSPKI,
				Insecure:    o.cfg.Edge.Insecure,
				Mux:         mux,
				DialTimeout: timeout,
			}
		case "websocket":
			hdr := http.Header{}
			for k, v := range p.Headers {
				hdr.Set(k, v)
			}
			d = &transport.WSDialer{
				URL:         p.URL,
				EdgeAddr:    p.EdgeAddr,
				Host:        p.Host,
				Fingerprint: transport.Fingerprint(p.Fingerprint),
				RootCAs:     roots,
				PinnedSPKI:  o.cfg.Edge.PinnedSPKI,
				Insecure:    o.cfg.Edge.Insecure,
				Headers:     hdr,
				Mux:         mux,
				DialTimeout: timeout,
			}
		default:
			return fmt.Errorf("edge.paths[%d]: unknown transport %q", i, p.Transport)
		}

		name := fmt.Sprintf("%s#%d", p.Transport, i)
		o.cands = append(o.cands, &candidate{
			name:   name,
			dialer: d,
			role:   role,
			weight: p.Weight,
		})
	}
	return nil
}

// Run keeps the tunnel up until ctx is cancelled.
func (o *Origin) Run(ctx context.Context) error {
	target := o.cfg.Tuning.Carriers
	if target < 1 {
		target = 1
	}

	o.log.Info("origin starting",
		"name", o.cfg.Name,
		"profile", string(o.cfg.Profile),
		"paths", len(o.cands),
		"carriers", target,
		"forwards", len(o.forwards),
		"memory_ceiling_mb", o.cfg.MemoryCeiling()/(1<<20),
	)

	// Bring the first carrier up by racing every candidate at once, so a
	// black-holed path costs a few hundred milliseconds instead of a full
	// dial timeout before the tunnel is usable.
	for o.set.Len() == 0 {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if o.raceFirst(ctx) {
			break
		}
		if !o.sleepBackoff(ctx) {
			return nil
		}
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			o.set.Close()
			return nil
		case <-o.set.Changed():
		case <-ticker.C:
		}

		if o.set.Len() == 0 {
			// Every path is down. Race again rather than filling slots one by
			// one; getting any carrier back is what matters.
			if !o.raceFirst(ctx) {
				o.sleepBackoff(ctx)
			}
			continue
		}
		for o.set.Len() < target {
			if !o.dialOne(ctx) {
				break
			}
		}
	}
}

// raceFirst dials every due candidate in parallel, staggered, and keeps the
// first carrier that completes registration. Losers are cancelled.
func (o *Origin) raceFirst(ctx context.Context) bool {
	due := o.dueCandidates()
	if len(due) == 0 {
		return false
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		cand *candidate
		err  error
	}
	results := make(chan result, len(due))

	for i, c := range due {
		stagger := time.Duration(i) * 300 * time.Millisecond
		go func(c *candidate, delay time.Duration) {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				results <- result{c, ctx.Err()}
				return
			}
			results <- result{c, o.connect(ctx, c)}
		}(c, stagger)
	}

	for range due {
		select {
		case r := <-results:
			if r.err == nil {
				return true
			}
			if !errors.Is(r.err, context.Canceled) {
				o.penalise(r.cand, r.err)
			}
		case <-ctx.Done():
			return false
		}
	}
	return false
}

// dialOne adds a single carrier, choosing the candidate with the best weight
// that is not currently backing off.
func (o *Origin) dialOne(ctx context.Context) bool {
	due := o.dueCandidates()
	if len(due) == 0 {
		return false
	}

	// Prefer data-capable paths with the highest weight and fewest failures.
	best := due[0]
	for _, c := range due[1:] {
		if c.fails < best.fails || (c.fails == best.fails && c.weight > best.weight) {
			best = c
		}
	}
	if err := o.connect(ctx, best); err != nil {
		o.penalise(best, err)
		return false
	}
	return true
}

func (o *Origin) dueCandidates() []*candidate {
	now := time.Now()
	o.mu.Lock()
	defer o.mu.Unlock()
	var due []*candidate
	for _, c := range o.cands {
		if now.After(c.nextTry) {
			due = append(due, c)
		}
	}
	return due
}

// penalise records a failure and schedules the next attempt with jittered
// exponential backoff.
func (o *Origin) penalise(c *candidate, err error) {
	b := o.cfg.Edge.Reconnect
	min := config.Duration(b.Min, time.Second)
	max := config.Duration(b.Max, 2*time.Minute)

	o.mu.Lock()
	c.fails++
	delay := float64(min)
	for i := 1; i < c.fails && delay < float64(max); i++ {
		delay *= b.Factor
	}
	if delay > float64(max) {
		delay = float64(max)
	}
	if b.Jitter > 0 {
		delay *= 1 + (o.rnd.Float64()*2-1)*b.Jitter
	}
	c.nextTry = time.Now().Add(time.Duration(delay))
	fails := c.fails
	o.mu.Unlock()

	o.log.Warn("path unavailable",
		"path", c.name, "fails", fails,
		"retry_in", time.Until(c.nextTry).Round(time.Millisecond), "err", err)
}

func (o *Origin) reward(c *candidate) {
	o.mu.Lock()
	c.fails = 0
	c.nextTry = time.Time{}
	o.mu.Unlock()
}

// sleepBackoff waits for the soonest retry, and reports false if ctx ended.
func (o *Origin) sleepBackoff(ctx context.Context) bool {
	o.mu.Lock()
	soonest := time.Now().Add(config.Duration(o.cfg.Edge.Reconnect.Max, 2*time.Minute))
	for _, c := range o.cands {
		if c.nextTry.Before(soonest) {
			soonest = c.nextTry
		}
	}
	o.mu.Unlock()

	wait := time.Until(soonest)
	if wait < 250*time.Millisecond {
		wait = 250 * time.Millisecond
	}
	select {
	case <-time.After(wait):
		return true
	case <-ctx.Done():
		return false
	}
}

// connect dials one candidate, authenticates, registers, and attaches the
// resulting carrier to the set.
func (o *Origin) connect(ctx context.Context, c *candidate) error {
	carrier, err := c.dialer.Dial(ctx)
	if err != nil {
		return err
	}

	ok := false
	defer func() {
		if !ok {
			carrier.Close()
		}
	}()

	ctrl, err := carrier.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	reg := protocol.Register{
		Version:   protocol.Version,
		Origin:    o.cfg.Name,
		Keepalive: int(config.Duration(o.cfg.Tuning.Keepalive, 10*time.Second).Seconds()),
		Takeover:  true,
		Join:      o.currentToken(),
	}
	for _, f := range o.cfg.Forwards {
		reg.Forwards = append(reg.Forwards, f.Public())
	}
	payload, err := json.Marshal(reg)
	if err != nil {
		return err
	}

	flags := uint8(0)
	if carrier.MaxDatagramSize() > 0 {
		flags |= auth.FlagDatagram
	}

	_ = ctrl.SetDeadline(time.Now().Add(config.Duration(o.cfg.Tuning.DialTimeout, 12*time.Second)))
	res, err := auth.ClientHandshake(ctrl, o.cred, flags, payload)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	_ = ctrl.SetDeadline(time.Time{})

	var done protocol.Registered
	if err := json.Unmarshal(res.Payload, &done); err != nil {
		return fmt.Errorf("registration reply: %w", err)
	}
	o.adoptToken(done.Token)

	entry := &pool.Entry{
		Carrier: carrier,
		Role:    c.role,
		Path:    c.name,
		Weight:  c.weight,
	}
	o.set.Add(entry)
	o.reward(c)
	ok = true

	o.log.Info("carrier up",
		"path", c.name,
		"transport", carrier.Transport(),
		"remote", carrier.RemoteAddr(),
		"session", res.SessionIDString()[:8],
		"carriers", o.set.Len(),
	)
	for _, a := range done.Accepted {
		o.log.Info("forward live", "name", a.Name, "proto", a.Proto, "ports", a.Ports, "count", a.Count)
	}
	for _, r := range done.Rejected {
		o.log.Error("forward refused", "name", r.Name, "ports", r.Ports, "reason", r.Reason)
	}

	go o.runControl(ctrl, carrier, entry)
	go o.acceptLoop(carrier, entry)
	return nil
}

func (o *Origin) currentToken() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.token
}

func (o *Origin) adoptToken(t string) {
	if t == "" {
		return
	}
	o.mu.Lock()
	o.token = t
	o.mu.Unlock()
}

// runControl pings the relay on the carrier's control stream. The interval is
// jittered: a heartbeat on an exact timer is a timing fingerprint that
// survives every layer of encryption below it.
func (o *Origin) runControl(ctrl transport.Stream, carrier transport.Carrier, e *pool.Entry) {
	defer carrier.Close()

	codec := protocol.NewCodec(ctrl)
	base := config.Duration(o.cfg.Tuning.Keepalive, 10*time.Second)

	pong := make(chan protocol.Control, 4)
	go func() {
		defer close(pong)
		for {
			var msg protocol.Control
			if err := codec.Read(&msg); err != nil {
				return
			}
			switch msg.Type {
			case protocol.MsgPong:
				select {
				case pong <- msg:
				default:
				}
			case protocol.MsgPing:
				_ = codec.Write(protocol.Control{Type: protocol.MsgPong, Seq: msg.Seq, TS: msg.TS})
			case protocol.MsgBye:
				o.log.Warn("relay closed session", "path", e.Path, "reason", msg.Reason)
				return
			}
		}
	}()

	var seq uint64
	misses := 0
	for {
		jitter := 1 + (o.jitter()*2-1)*0.25
		select {
		case <-time.After(time.Duration(float64(base) * jitter)):
		case <-carrier.Done():
			return
		}

		seq++
		sent := time.Now()
		if err := codec.Write(protocol.Control{Type: protocol.MsgPing, Seq: seq, TS: protocol.Now()}); err != nil {
			o.log.Warn("keepalive write failed", "path", e.Path, "err", err)
			return
		}

		select {
		case _, ok := <-pong:
			if !ok {
				return
			}
			misses = 0
			e.ObserveLatency(time.Since(sent))
		case <-time.After(base):
			misses++
			if misses >= 3 {
				o.log.Warn("carrier unresponsive, dropping", "path", e.Path, "missed", misses)
				return
			}
		case <-carrier.Done():
			return
		}
	}
}

func (o *Origin) jitter() float64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.rnd.Float64()
}

// acceptLoop serves the streams the relay opens for each user connection.
func (o *Origin) acceptLoop(carrier transport.Carrier, e *pool.Entry) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-carrier.Done()
		cancel()
	}()

	for {
		st, err := carrier.AcceptStream(ctx)
		if err != nil {
			return
		}
		go o.serveStream(st, e)
	}
}

// serveStream reads the open request and connects the stream to a backend.
func (o *Origin) serveStream(st transport.Stream, e *pool.Entry) {
	defer st.Close()

	codec := protocol.NewCodec(st)
	var req protocol.OpenRequest
	_ = st.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err := codec.Read(&req); err != nil {
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	f, ok := o.forwards[req.Forward]
	if !ok {
		o.log.Warn("relay asked for an unknown forward", "name", req.Forward)
		return
	}
	target, err := f.Resolve(req.Port)
	if err != nil {
		o.log.Error("cannot resolve target", "forward", f.Name, "port", req.Port, "err", err)
		return
	}

	switch req.Proto {
	case protocol.ProtoUDP:
		o.serveUDP(st, f, req, target, e)
	default:
		o.serveTCP(st, f, req, target, e)
	}
}

func (o *Origin) serveTCP(st transport.Stream, f protocol.Forward, req protocol.OpenRequest, target string, e *pool.Entry) {
	d := net.Dialer{Timeout: 10 * time.Second}
	backend, err := d.Dial("tcp", target)
	if err != nil {
		o.log.Warn("backend unreachable", "forward", f.Name, "target", target, "err", err)
		return
	}
	defer backend.Close()
	tuneTCP(backend)

	if f.ProxyProtocol > 0 {
		if err := writeProxyHeader(backend, f.ProxyProtocol, req, backend.LocalAddr(), false); err != nil {
			o.log.Warn("proxy protocol header failed", "forward", f.Name, "err", err)
			return
		}
	}

	in, out := Splice(st, backend, o.cfg.Tuning.CopyBuffer)
	e.AddTraffic(uint64(in), uint64(out))
}

// serveUDP bridges a framed stream to a UDP socket aimed at the backend. One
// stream carries one client's flow, which keeps the mapping trivial and lets
// the relay expire it by closing the stream.
func (o *Origin) serveUDP(st transport.Stream, f protocol.Forward, req protocol.OpenRequest, target string, e *pool.Entry) {
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		o.log.Warn("bad udp target", "forward", f.Name, "target", target, "err", err)
		return
	}
	sock, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		o.log.Warn("udp backend unreachable", "forward", f.Name, "target", target, "err", err)
		return
	}
	defer sock.Close()

	framer := wire.NewFramer(st, 64<<10)
	idle := 90 * time.Second

	var wg sync.WaitGroup
	wg.Add(2)

	// Tunnel -> backend.
	go func() {
		defer wg.Done()
		defer sock.Close()
		buf := make([]byte, wire.MaxPacketSize)
		for {
			_ = st.SetReadDeadline(time.Now().Add(idle))
			n, err := framer.ReadPacket(buf)
			if err != nil {
				return
			}
			if _, err := sock.Write(buf[:n]); err != nil {
				return
			}
			e.AddTraffic(uint64(n), 0)
		}
	}()

	// Backend -> tunnel.
	go func() {
		defer wg.Done()
		defer st.Close()
		buf := make([]byte, 65535)
		for {
			_ = sock.SetReadDeadline(time.Now().Add(idle))
			n, err := sock.Read(buf)
			if err != nil {
				return
			}
			if err := framer.WriteAndFlush(buf[:n]); err != nil {
				return
			}
			e.AddTraffic(0, uint64(n))
		}
	}()

	wg.Wait()
}

// writeProxyHeader tells the backend who the real client is.
func writeProxyHeader(backend net.Conn, version int, req protocol.OpenRequest, localAddr net.Addr, udp bool) error {
	src, err := proxyproto.ParseAddrPort(req.Client)
	if err != nil {
		return fmt.Errorf("client address %q: %w", req.Client, err)
	}
	dst, err := proxyproto.ParseAddrPort(localAddr.String())
	if err != nil {
		return fmt.Errorf("local address: %w", err)
	}
	// The destination the client believed it was reaching is the edge port,
	// which is what a backend's logs and GeoIP rules should show.
	dst = setPort(dst, uint16(req.Port))
	return proxyproto.Write(backend, version, src, dst, udp)
}

// setPort replaces the port of an AddrPort.
func setPort(ap netip.AddrPort, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr(), port)
}

