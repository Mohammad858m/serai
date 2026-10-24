package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
)

// ErrListenerClosed is returned by Accept after Close.
var ErrListenerClosed = errors.New("transport: listener closed")

// AcceptMux adapts an accepted TLS connection that negotiated the mtunnel
// ALPN into a Carrier. The relay calls this after it has decided, from the
// SNI, that a connection belongs to the tunnel rather than to a backend.
func AcceptMux(conn net.Conn, opts MuxOptions) (Carrier, error) {
	return NewMuxCarrier("tls", conn, false, opts)
}

// SingleConnListener feeds exactly one accepted connection to an http.Server,
// which is how a connection that turned out to be plain HTTPS gets handed to
// the decoy site without running a second listener for it.
type SingleConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
}

// NewSingleConnListener wraps one connection.
func NewSingleConnListener(c net.Conn, addr net.Addr) *SingleConnListener {
	return &SingleConnListener{conn: c, addr: addr}
}

func (l *SingleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil, io.EOF
	}
	c := l.conn
	l.conn = nil
	return c, nil
}

func (l *SingleConnListener) Close() error   { return nil }
func (l *SingleConnListener) Addr() net.Addr { return l.addr }

// DecoyHandler reverse-proxies to upstream, or serves a bland 404 when
// upstream is empty or unparseable.
//
// This is what an active prober gets. A relay that answers a probe with a
// reset, a TLS alert, or an obviously synthetic page is a relay that has
// identified itself; one that serves a real site is just a web server.
func DecoyHandler(upstream string) http.Handler {
	if upstream != "" {
		if u, err := url.Parse(upstream); err == nil && u.Host != "" {
			proxy := httputil.NewSingleHostReverseProxy(u)
			proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
				WriteDecoy(w)
			}
			inner := proxy.Director
			proxy.Director = func(r *http.Request) {
				inner(r)
				// Present the upstream's own Host so it serves its real site.
				r.Host = u.Host
			}
			return proxy
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { WriteDecoy(w) })
}

// WriteDecoy emits a response indistinguishable from a default nginx 404.
func WriteDecoy(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n"+
		"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"+
		"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
}

// MultiListener fans several listeners into one Accept stream, so the relay
// can wait on QUIC and TCP with a single loop.
type MultiListener struct {
	listeners []Listener
	out       chan acceptResult
	closed    chan struct{}
	once      sync.Once
}

type acceptResult struct {
	carrier Carrier
	err     error
	from    string
}

// NewMultiListener starts a pump goroutine per listener.
func NewMultiListener(ls ...Listener) *MultiListener {
	m := &MultiListener{
		listeners: ls,
		out:       make(chan acceptResult, len(ls)+8),
		closed:    make(chan struct{}),
	}
	for _, l := range ls {
		go m.pump(l)
	}
	return m
}

func (m *MultiListener) pump(l Listener) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-m.closed
		cancel()
	}()

	for {
		c, err := l.Accept(ctx)
		if err != nil {
			select {
			case m.out <- acceptResult{err: err, from: l.Name()}:
			case <-m.closed:
			}
			return
		}
		select {
		case m.out <- acceptResult{carrier: c, from: l.Name()}:
		case <-m.closed:
			c.Close()
			return
		}
	}
}

// Accept returns the next carrier from any listener. A closed listener is
// skipped rather than taking the others down with it.
func (m *MultiListener) Accept(ctx context.Context) (Carrier, error) {
	for {
		select {
		case r := <-m.out:
			if r.err != nil {
				if errors.Is(r.err, ErrListenerClosed) || errors.Is(r.err, context.Canceled) {
					continue
				}
				return nil, r.err
			}
			return r.carrier, nil
		case <-m.closed:
			return nil, ErrListenerClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Close shuts every listener down.
func (m *MultiListener) Close() error {
	m.once.Do(func() { close(m.closed) })
	var first error
	for _, l := range m.listeners {
		if err := l.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
