package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// bufPools keeps one pool per buffer size so a config change does not mix
// sizes in a single pool. Pooling matters here: at a thousand concurrent flows
// a fresh 32 KiB buffer per direction per connection is 64 MiB of garbage
// churned continuously, which shows up as GC CPU rather than as throughput.
var (
	bufPoolsMu sync.Mutex
	bufPools   = map[int]*sync.Pool{}
)

func bufPool(size int) *sync.Pool {
	bufPoolsMu.Lock()
	defer bufPoolsMu.Unlock()
	if p, ok := bufPools[size]; ok {
		return p
	}
	p := &sync.Pool{New: func() any {
		b := make([]byte, size)
		return &b
	}}
	bufPools[size] = p
	return p
}

// closeWriter is implemented by TCP connections and by both multiplexers'
// streams. Half-closing instead of hard-closing is what lets a backend see a
// clean end-of-request and reply, rather than a reset mid-response.
type closeWriter interface{ CloseWrite() error }

func halfClose(c io.Closer) {
	if cw, ok := c.(closeWriter); ok {
		if err := cw.CloseWrite(); err == nil {
			return
		}
	}
	c.Close()
}

// pipe copies src into dst with a pooled buffer and reports the byte count.
func pipe(dst io.Writer, src io.Reader, size int) (int64, error) {
	if size <= 0 {
		size = 32 << 10
	}
	p := bufPool(size)
	bufp := p.Get().(*[]byte)
	defer p.Put(bufp)
	return io.CopyBuffer(dst, src, *bufp)
}

// Splice relays both directions between a and b until both are done, and
// returns the bytes that travelled a->b and b->a.
//
// Each direction half-closes its destination when its source ends, so a
// request/response protocol completes normally instead of being reset.
func Splice(a, b io.ReadWriteCloser, size int) (int64, int64) {
	var toB, toA atomic.Int64

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := pipe(b, a, size)
		toB.Store(n)
		halfClose(b)
	}()
	go func() {
		defer wg.Done()
		n, _ := pipe(a, b, size)
		toA.Store(n)
		halfClose(a)
	}()

	wg.Wait()
	a.Close()
	b.Close()
	return toB.Load(), toA.Load()
}

// tuneTCP applies the socket options that matter for an interactive tunnel.
// NoDelay is the important one: without it, Nagle holds a small write until an
// ACK arrives, adding a full round trip to every short exchange, which is most
// of what a VPN carries.
func tuneTCP(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
}
