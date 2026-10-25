package relay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/Mohammad858m/serai/internal/auth"
	"github.com/Mohammad858m/serai/internal/config"
	"github.com/Mohammad858m/serai/internal/pool"
	"github.com/Mohammad858m/serai/internal/protocol"
	"github.com/Mohammad858m/serai/internal/sniff"
	"github.com/Mohammad858m/serai/internal/transport"
	"github.com/Mohammad858m/serai/internal/wire"
)

// Edge is the relay users connect to. It holds no backend addresses, no panel
// and no routing policy of its own: an authenticated origin tells it which
// ports to open, and it quotes a rule name back when forwarding.
//
// It exposes one TCP port and one UDP port, both normally 443. User traffic
// and tunnel traffic share them, separated by SNI, so there is no cluster of
// unusual open ports for a scanner to notice -- which is how relays are found
// long before any single connection is analysed.
type Edge struct {
	cfg    *config.Config
	log    *slog.Logger
	cred   auth.Credentials
	replay *auth.ReplayGuard

	tlsConf *tls.Config
	httpSrv *http.Server

	mu       sync.RWMutex
	sessions map[string]*session // by token
	byOrigin map[string]*session // by origin name, for takeover
	sniIndex map[string]sniRoute // lowercase SNI -> destination
}

// sniRoute is where a user connection with a given SNI should go.
type sniRoute struct {
	sess    *session
	forward string
	port    int
}

// NewEdge builds a relay from a validated config.
func NewEdge(cfg *config.Config, log *slog.Logger) (*Edge, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}

	e := &Edge{
		cfg:      cfg,
		log:      log,
		cred:     auth.NewCredentials(cfg.PSKBytes()),
		replay:   auth.NewReplayGuard(),
		sessions: map[string]*session{},
		byOrigin: map[string]*session{},
		sniIndex: map[string]sniRoute{},
		// No CipherSuites restriction, deliberately.
		//
		// An earlier version narrowed this to six AES-GCM suites, reasoning
		// that AES-NI makes them cheaper per gigabyte than ChaCha20. That
		// reasoning does not apply: the field is ignored for TLS 1.3, which is
		// what every client here negotiates, and Go already prefers AES-GCM
		// when the CPU reports AES-NI. So it bought nothing and cost two
		// things -- it could only ever turn a working handshake into a
		// handshake_failure with some client not anticipated here, and a
		// server offering an unusually narrow cipher list is itself
		// distinguishable from the ordinary web server this is meant to
		// resemble.
		tlsConf: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Server.WSPath, e.handleWebSocket)
	mux.Handle("/", transport.DecoyHandler(cfg.Server.DecoyUpstream))
	e.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return e, nil
}

// Run serves until ctx is cancelled.
func (e *Edge) Run(ctx context.Context) error {
	s := e.cfg.Server

	ln, err := net.Listen("tcp", s.ControlAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.ControlAddr, err)
	}
	defer ln.Close()

	e.log.Info("edge listening",
		"tcp", ln.Addr().String(),
		"quic", s.QUICAddr,
		"tunnel_sni", s.TunnelSNI,
		"ws_path", s.WSPath,
		"decoy", s.DecoyUpstream,
		"profile", string(e.cfg.Profile),
	)

	if s.QUICAddr != "" {
		qln, err := transport.ListenQUIC(s.QUICAddr, e.tlsConf,
			config.Duration(e.cfg.Tuning.Keepalive, 10*time.Second))
		if err != nil {
			// A missing UDP port is not fatal: the TCP paths still work, and
			// losing QUIC is exactly the case the fallback exists for.
			e.log.Warn("quic disabled", "addr", s.QUICAddr, "err", err)
		} else {
			defer qln.Close()
			go e.acceptCarriers(ctx, qln)
		}
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("accept: %w", err)
		}
		go e.route(conn)
	}
}

// acceptCarriers pumps a transport listener into the session registry.
func (e *Edge) acceptCarriers(ctx context.Context, l transport.Listener) {
	for {
		c, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				e.log.Warn("carrier listener stopped", "listener", l.Name(), "err", err)
			}
			return
		}
		go e.onCarrier(c)
	}
}

// route decides what an inbound TCP connection on the shared port is.
//
// The SNI is read without terminating TLS, so a user's session still
// negotiates end to end with Xray on the origin. The relay cannot decrypt it
// and does not need to.
func (e *Edge) route(conn net.Conn) {
	tuneTCP(conn)

	name, peeked, err := sniff.ServerName(conn, 10*time.Second)
	if err != nil && name == "" {
		if errors.Is(err, sniff.ErrNotTLS) || errors.Is(err, sniff.ErrNoSNI) {
			// Not TLS, or TLS without SNI: let the decoy answer it.
			e.log.Debug("no usable sni, serving decoy", "peer", conn.RemoteAddr(), "err", err)
			e.serveLocalTLSSNI(peeked, "")
			return
		}
		e.log.Debug("could not read client hello", "peer", conn.RemoteAddr(), "err", err)
		conn.Close()
		return
	}

	host := strings.ToLower(strings.TrimSuffix(name, "."))
	if host == strings.ToLower(e.cfg.Server.TunnelSNI) {
		e.serveLocalTLSSNI(peeked, host)
		return
	}

	e.mu.RLock()
	route, ok := e.sniIndex[host]
	e.mu.RUnlock()
	if !ok {
		e.log.Debug("sni not routed, serving decoy", "sni", host, "peer", conn.RemoteAddr())
		e.serveLocalTLSSNI(peeked, host)
		return
	}

	e.dispatchTCP(route.sess, route.forward, route.port, peeked)
}

// serveLocalTLSSNI terminates TLS here and either accepts a tunnel carrier
// (ALPN) or serves the decoy site (HTTP). sni is what the client asked for,
// carried through only so a rejected handshake can be logged against it.
func (e *Edge) serveLocalTLSSNI(conn net.Conn, sni string) {
	conf := e.tlsConf.Clone()
	conf.NextProtos = []string{transport.ALPN, "http/1.1"}

	tconn := tls.Server(conn, conf)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := tconn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		// A failed handshake used to be dropped in silence, on the grounds
		// that scanners and stray probes are noise. That also made a genuine
		// configuration fault invisible: the far side reports only "remote
		// error: handshake failure" and this side logs nothing at all, which
		// is the least debuggable outcome available. Log it at debug, where
		// an operator can turn it on without the noise becoming a problem.
		e.log.Debug("tls handshake rejected",
			"sni", sni,
			"peer", conn.RemoteAddr(),
			"err", err)
		conn.Close()
		return
	}

	st := tconn.ConnectionState()
	e.log.Debug("tls handshake ok",
		"sni", st.ServerName,
		"version", tlsVersionName(st.Version),
		"alpn", st.NegotiatedProtocol,
		"peer", conn.RemoteAddr())

	if tconn.ConnectionState().NegotiatedProtocol == transport.ALPN {
		carrier, err := transport.AcceptMux(tconn, e.cfg.MuxOptions(transport.RoleBoth))
		if err != nil {
			tconn.Close()
			return
		}
		e.onCarrier(carrier)
		return
	}
	e.httpSrv.Serve(transport.NewSingleConnListener(tconn, conn.LocalAddr()))
}

func (e *Edge) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
		// The upgrade itself is not the security boundary; the pre-shared-key
		// handshake that follows is. An unauthenticated client gets a normal
		// websocket that then goes nowhere, which is what a web app would do.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}

	carrier, err := transport.AcceptWebSocket(ws, e.cfg.MuxOptions(transport.RoleBoth))
	if err != nil {
		ws.Close(websocket.StatusInternalError, "")
		return
	}
	e.onCarrier(carrier)

	// The hijacked connection is ours now; hold the handler until it dies.
	<-carrier.Done()
}

// onCarrier authenticates a new carrier and attaches it to a session.
func (e *Edge) onCarrier(c transport.Carrier) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	ctrl, err := c.AcceptStream(ctx)
	cancel()
	if err != nil {
		c.Close()
		return
	}

	lookup := func(id [8]byte) (auth.Credentials, bool) {
		if id == e.cred.KeyID {
			return e.cred, true
		}
		return auth.Credentials{}, false
	}

	var (
		sess   *session
		joined bool
	)
	_ = ctrl.SetDeadline(time.Now().Add(20 * time.Second))
	res, err := auth.ServerHandshake(ctrl, lookup, e.replay, func(h auth.Hello, r auth.Result) (uint8, []byte, error) {
		var reg protocol.Register
		if err := json.Unmarshal(h.Payload, &reg); err != nil {
			return auth.StatusUnavailable, nil, err
		}
		s, j, reply, err := e.register(reg, c)
		if err != nil {
			return auth.StatusUnavailable, nil, err
		}
		sess, joined = s, j
		payload, err := json.Marshal(reply)
		return auth.StatusOK, payload, err
	})
	_ = ctrl.SetDeadline(time.Time{})

	if err != nil {
		// Authentication failure is deliberately silent. The peer learns
		// nothing, and a prober cannot tell a tunnel from a web server.
		if !errors.Is(err, auth.ErrBadMAC) {
			e.log.Debug("carrier rejected", "transport", c.Transport(), "err", err)
		}
		c.Close()
		return
	}

	entry := &pool.Entry{
		Carrier: c,
		Role:    transport.RoleBoth,
		Path:    c.Transport(),
		Weight:  1,
	}
	sess.carriers.Add(entry)

	e.log.Info("carrier joined",
		"origin", sess.origin,
		"transport", c.Transport(),
		"remote", c.RemoteAddr(),
		"session", res.SessionIDString()[:8],
		"rejoin", joined,
		"carriers", sess.carriers.Len(),
	)

	go e.serveControl(sess, ctrl, c)
}

// serveControl answers keepalives and notices when a carrier goes quiet.
func (e *Edge) serveControl(s *session, ctrl transport.Stream, c transport.Carrier) {
	defer c.Close()

	codec := protocol.NewCodec(ctrl)
	idle := 3 * config.Duration(e.cfg.Tuning.Keepalive, 10*time.Second)

	for {
		_ = ctrl.SetReadDeadline(time.Now().Add(idle))
		var msg protocol.Control
		if err := codec.Read(&msg); err != nil {
			return
		}
		switch msg.Type {
		case protocol.MsgPing:
			if err := codec.Write(protocol.Control{Type: protocol.MsgPong, Seq: msg.Seq, TS: msg.TS}); err != nil {
				return
			}
		case protocol.MsgBye:
			e.log.Info("origin said goodbye", "origin", s.origin, "reason", msg.Reason)
			return
		}
	}
}

// --- sessions ---------------------------------------------------------------

// session is one origin's registration: its carriers, its rules, and the
// listeners opened on its behalf.
type session struct {
	edge     *Edge
	token    string
	origin   string
	carriers *pool.Set
	forwards map[string]protocol.Forward

	mu        sync.Mutex
	listeners []io.Closer
	udpFlows  map[string]*udpFlow
	closed    bool

	cancel context.CancelFunc
}

// register creates or rejoins a session and binds the requested ports.
func (e *Edge) register(reg protocol.Register, c transport.Carrier) (*session, bool, protocol.Registered, error) {
	if reg.Join != "" {
		e.mu.RLock()
		s, ok := e.sessions[reg.Join]
		e.mu.RUnlock()
		if ok && !s.isClosed() {
			return s, true, protocol.Registered{
				Version:  protocol.Version,
				Edge:     e.cfg.Name,
				Token:    s.token,
				Joined:   true,
				Accepted: s.acceptedList(),
			}, nil
		}
		// An unknown token is not an error: fall through to a fresh
		// registration so a restarted relay heals without operator action.
	}

	e.mu.Lock()
	if n := len(e.sessions); n >= e.cfg.Server.MaxSessions {
		e.mu.Unlock()
		return nil, false, protocol.Registered{}, fmt.Errorf("relay at capacity (%d sessions)", n)
	}
	prev, hadPrev := e.byOrigin[reg.Origin]
	e.mu.Unlock()

	if hadPrev {
		if !reg.Takeover {
			return nil, false, protocol.Registered{}, fmt.Errorf("origin %q already registered", reg.Origin)
		}
		// Replacing the old session immediately is what makes a reconnect after
		// a dead TCP connection fast: without it the ports stay bound to a
		// session whose carriers will not time out for minutes.
		e.log.Info("replacing previous session", "origin", reg.Origin)
		prev.close()
	}

	token := newToken()
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{
		edge:     e,
		token:    token,
		origin:   reg.Origin,
		carriers: pool.NewSet(),
		forwards: map[string]protocol.Forward{},
		udpFlows: map[string]*udpFlow{},
		cancel:   cancel,
	}

	reply := protocol.Registered{
		Version: protocol.Version,
		Edge:    e.cfg.Name,
		Token:   token,
	}

	for _, f := range reg.Forwards {
		// The origin sends the spec, not the expanded list; expand it here.
		ports, err := f.ExpandPorts()
		if err != nil {
			reply.Rejected = append(reply.Rejected, protocol.Rejected{
				Name: f.Name, Ports: f.EdgePorts, Reason: err.Error(),
			})
			continue
		}
		f.Ports = ports

		acc, rej := s.bind(ctx, f)
		if rej != nil {
			reply.Rejected = append(reply.Rejected, *rej)
			continue
		}
		if acc != nil {
			s.forwards[f.Name] = f
			reply.Accepted = append(reply.Accepted, *acc)
		}
	}

	if len(reply.Accepted) == 0 {
		s.close()
		return nil, false, protocol.Registered{}, errors.New("no forwarding rule could be bound")
	}

	e.mu.Lock()
	e.sessions[token] = s
	e.byOrigin[reg.Origin] = s
	e.mu.Unlock()
	e.reindexSNI()

	go s.reap(ctx)
	return s, false, reply, nil
}

// bind opens the listeners for one rule, reporting what was accepted.
func (s *session) bind(ctx context.Context, f protocol.Forward) (*protocol.Accepted, *protocol.Rejected) {
	e := s.edge
	reject := func(reason string, port int) (*protocol.Accepted, *protocol.Rejected) {
		return nil, &protocol.Rejected{
			Name:   f.Name,
			Ports:  strconv.Itoa(port),
			Reason: reason,
		}
	}

	controlPort := portOf(e.cfg.Server.ControlAddr)
	quicPort := portOf(e.cfg.Server.QUICAddr)

	var bound []int
	for _, p := range f.Ports {
		// The shared port cannot be bound twice. With an SNI it needs no
		// listener at all; without one there is nothing to demultiplex on.
		//
		// allow_ports exists to limit which ports an origin can make this
		// relay open. Serving the relay's own port by SNI opens nothing, so
		// it is exempt -- otherwise the common case of one rule on 443 would
		// need 443 listed in allow_ports, which reads like permission to
		// rebind the relay's own listener.
		if p == controlPort {
			if len(f.SNI) == 0 {
				return reject(fmt.Sprintf("port %d is the relay's own port; give this rule an \"sni\" so it can share it", p), p)
			}
			bound = append(bound, p)
			continue
		}

		if !protocol.PortAllowed(e.cfg.Server.AllowPorts, p) {
			return reject(fmt.Sprintf("port %d is outside server.allow_ports (%s)",
				p, e.cfg.Server.AllowPorts), p)
		}
		if f.WantsTCP() {
			if err := s.listenTCP(ctx, f.Name, p); err != nil {
				return reject(fmt.Sprintf("tcp/%d: %v", p, err), p)
			}
		}
		if f.WantsUDP() {
			if p == quicPort {
				return reject(fmt.Sprintf("udp/%d collides with the relay's QUIC port", p), p)
			}
			if err := s.listenUDP(ctx, f.Name, p); err != nil {
				return reject(fmt.Sprintf("udp/%d: %v", p, err), p)
			}
		}
		bound = append(bound, p)
	}

	return &protocol.Accepted{
		Name:  f.Name,
		Proto: f.Proto,
		Ports: f.EdgePorts,
		Count: len(bound),
	}, nil
}

func (s *session) listenTCP(ctx context.Context, forward string, port int) error {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return err
	}
	s.addListener(ln)

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				s.edge.log.Debug("forward listener stopped",
					"forward", forward, "port", port, "err", err)
				return
			}
			tuneTCP(conn)
			go s.edge.dispatchTCP(s, forward, port, conn)
		}
	}()
	return nil
}

// dispatchTCP hands a user connection to the origin.
//
// The open request and the user's first bytes go out together and the reply is
// never waited for. A request/response exchange therefore costs exactly the
// round trips the user's own protocol needs, with none added by the tunnel --
// the difference between a TLS handshake that completes in one round trip and
// one that takes two.
func (e *Edge) dispatchTCP(s *session, forward string, port int, conn net.Conn) {
	defer conn.Close()

	e.log.Debug("user connection", "forward", forward, "port", port, "client", conn.RemoteAddr())

	st, entry, release, err := s.carriers.OpenStream(context.Background(), transport.RoleData)
	if err != nil {
		e.log.Warn("no carrier for user connection",
			"forward", forward, "port", port, "client", conn.RemoteAddr(), "err", err)
		return
	}
	defer release()
	defer st.Close()

	req := protocol.OpenRequest{
		Forward: forward,
		Proto:   protocol.ProtoTCP,
		Port:    port,
		Client:  conn.RemoteAddr().String(),
	}
	if err := protocol.NewCodec(st).Write(req); err != nil {
		// Previously silent, which made a dead carrier look identical to a
		// backend that simply never answered.
		e.log.Warn("could not send open request",
			"forward", forward, "port", port, "transport", entry.Carrier.Transport(), "err", err)
		return
	}

	in, out := Splice(st, conn, e.cfg.Tuning.CopyBuffer)
	entry.AddTraffic(uint64(out), uint64(in))
	e.log.Debug("user connection closed",
		"forward", forward, "port", port, "to_origin", out, "to_client", in)
}

// --- UDP ---------------------------------------------------------------------

// udpFlow is one client's UDP conversation, carried on its own stream.
//
// UDP is where most tunnels are weakest, and it is what Hysteria2, TUIC and
// WireGuard inbounds need. Each client address gets a stream with framed
// datagrams and an idle timer, so the flow table stays bounded and a burst of
// spoofed source addresses cannot grow it without limit.
type udpFlow struct {
	framer *wire.Framer
	stream transport.Stream
	last   time.Time
	mu     sync.Mutex
}

const (
	udpIdleTimeout = 90 * time.Second
	maxUDPFlows    = 8192
)

func (s *session) listenUDP(ctx context.Context, forward string, port int) error {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return err
	}
	s.addListener(pc)

	go func() {
		defer pc.Close()
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			s.forwardUDP(ctx, pc, forward, port, addr, buf[:n])
		}
	}()
	return nil
}

func (s *session) forwardUDP(ctx context.Context, pc *net.UDPConn, forward string, port int, addr *net.UDPAddr, pkt []byte) {
	key := forward + "|" + strconv.Itoa(port) + "|" + addr.String()

	s.mu.Lock()
	flow, ok := s.udpFlows[key]
	if ok {
		s.mu.Unlock()
	} else {
		if len(s.udpFlows) >= maxUDPFlows {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		st, entry, release, err := s.carriers.OpenStream(ctx, transport.RoleData)
		if err != nil {
			return
		}
		req := protocol.OpenRequest{
			Forward: forward,
			Proto:   protocol.ProtoUDP,
			Port:    port,
			Client:  addr.String(),
		}
		if err := protocol.NewCodec(st).Write(req); err != nil {
			release()
			st.Close()
			return
		}

		flow = &udpFlow{framer: wire.NewFramer(st, 64<<10), stream: st, last: time.Now()}

		s.mu.Lock()
		if existing, dup := s.udpFlows[key]; dup {
			s.mu.Unlock()
			release()
			st.Close()
			flow = existing
		} else {
			s.udpFlows[key] = flow
			s.mu.Unlock()

			// Reply path: origin -> user.
			go func() {
				defer func() {
					release()
					st.Close()
					s.mu.Lock()
					delete(s.udpFlows, key)
					s.mu.Unlock()
				}()
				rbuf := make([]byte, wire.MaxPacketSize)
				for {
					_ = st.SetReadDeadline(time.Now().Add(udpIdleTimeout))
					n, err := flow.framer.ReadPacket(rbuf)
					if err != nil {
						return
					}
					if _, err := pc.WriteToUDP(rbuf[:n], addr); err != nil {
						return
					}
					entry.AddTraffic(uint64(n), 0)
				}
			}()
		}
	}

	flow.mu.Lock()
	flow.last = time.Now()
	err := flow.framer.WriteAndFlush(pkt)
	flow.mu.Unlock()
	if err != nil {
		flow.stream.Close()
	}
}

// --- session plumbing -------------------------------------------------------

func (s *session) addListener(c io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return
	}
	s.listeners = append(s.listeners, c)
}

func (s *session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *session) acceptedList() []protocol.Accepted {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]protocol.Accepted, 0, len(s.forwards))
	for _, f := range s.forwards {
		out = append(out, protocol.Accepted{
			Name:  f.Name,
			Proto: f.Proto,
			Ports: f.EdgePorts,
			Count: len(f.Ports),
		})
	}
	return out
}

// reap closes a session whose carriers have all been gone for a grace period.
//
// The grace period matters: a brief outage should not unbind the ports, both
// because rebinding races with the old listener and because users reconnecting
// into a refused port is a worse signal than users waiting a few seconds.
func (s *session) reap(ctx context.Context) {
	const grace = 90 * time.Second
	var emptySince time.Time

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.carriers.Changed():
		case <-ticker.C:
		}

		if s.carriers.Len() > 0 {
			emptySince = time.Time{}
			continue
		}
		if emptySince.IsZero() {
			emptySince = time.Now()
			continue
		}
		if time.Since(emptySince) > grace {
			s.edge.log.Warn("session expired", "origin", s.origin, "after", grace)
			s.close()
			return
		}
	}
}

func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	listeners := s.listeners
	s.listeners = nil
	flows := s.udpFlows
	s.udpFlows = map[string]*udpFlow{}
	s.mu.Unlock()

	for _, l := range listeners {
		l.Close()
	}
	for _, f := range flows {
		f.stream.Close()
	}
	s.carriers.Close()
	s.cancel()

	e := s.edge
	e.mu.Lock()
	delete(e.sessions, s.token)
	if cur, ok := e.byOrigin[s.origin]; ok && cur == s {
		delete(e.byOrigin, s.origin)
	}
	e.mu.Unlock()
	e.reindexSNI()
}

// reindexSNI rebuilds the SNI routing table from every live session.
func (e *Edge) reindexSNI() {
	e.mu.Lock()
	defer e.mu.Unlock()

	idx := map[string]sniRoute{}
	for _, s := range e.sessions {
		s.mu.Lock()
		forwards := make([]protocol.Forward, 0, len(s.forwards))
		for _, f := range s.forwards {
			forwards = append(forwards, f)
		}
		s.mu.Unlock()

		for _, f := range forwards {
			port := portOf(e.cfg.Server.ControlAddr)
			if len(f.Ports) > 0 {
				port = f.Ports[0]
			}
			for _, name := range f.SNI {
				host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
				if host == "" || host == strings.ToLower(e.cfg.Server.TunnelSNI) {
					continue
				}
				idx[host] = sniRoute{sess: s, forward: f.Name, port: port}
			}
		}
	}
	e.sniIndex = idx
}

// Sessions reports live sessions for the status endpoint.
func (e *Edge) Sessions() map[string][]pool.Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := map[string][]pool.Stats{}
	for _, s := range e.sessions {
		out[s.origin] = s.carriers.Snapshot()
	}
	return out
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func newToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// portOf extracts the port from a listen address like ":443" or "1.2.3.4:443".
func portOf(addr string) int {
	if addr == "" {
		return -1
	}
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return -1
	}
	return n
}
