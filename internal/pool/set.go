// Package pool manages the set of carriers that together form one tunnel.
//
// Running several independent carriers instead of one connection is the single
// biggest throughput and tail-latency win in this design:
//
//   - A reliable multiplexer over one TCP connection suffers head-of-line
//     blocking. One lost segment stalls every user flow sharing it. With N
//     carriers a loss event stalls only the flows on that carrier.
//   - Providers routinely shape per-flow rather than per-host, so one
//     connection hits a ceiling that four do not.
//   - Carriers can sit on different transports at once, so losing QUIC to a
//     UDP block costs only the flows already on it.
//
// New flows are assigned by shortest queue, biased by weight and by each
// carrier's measured open latency, which makes a degraded path drain itself
// instead of having to be detected and declared dead.
package pool

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Mohammad858m/serai/internal/transport"
)

// ErrNoCarrier means the tunnel currently has no usable path.
var ErrNoCarrier = errors.New("pool: no carrier available")

// Entry is one carrier plus the statistics used to schedule onto it.
type Entry struct {
	Carrier transport.Carrier
	Role    transport.Role
	// Path is the configured candidate name, stable across reconnects.
	Path   string
	Weight int

	active   atomic.Int64
	streams  atomic.Uint64
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	failures atomic.Uint64

	latMu  sync.Mutex
	latEWMA time.Duration

	since time.Time
}

// Active is the number of streams currently open on this carrier.
func (e *Entry) Active() int64 { return e.active.Load() }

// Latency is the smoothed stream-open latency.
func (e *Entry) Latency() time.Duration {
	e.latMu.Lock()
	defer e.latMu.Unlock()
	return e.latEWMA
}

// observe folds a new latency sample into the EWMA.
func (e *Entry) observe(d time.Duration) {
	e.latMu.Lock()
	defer e.latMu.Unlock()
	if e.latEWMA == 0 {
		e.latEWMA = d
		return
	}
	// alpha = 0.2: fast enough to notice a path going bad within a few flows,
	// slow enough that one unlucky sample does not reroute everything.
	e.latEWMA = time.Duration(0.8*float64(e.latEWMA) + 0.2*float64(d))
}

// ObserveLatency folds an externally measured round trip into the carrier's
// score. The control-stream keepalive calls this, so the scheduler learns a
// path is getting slower from the heartbeat rather than waiting for enough
// user flows to reveal it.
func (e *Entry) ObserveLatency(d time.Duration) { e.observe(d) }

// AddTraffic records relayed bytes for the status view.
func (e *Entry) AddTraffic(in, out uint64) {
	e.bytesIn.Add(in)
	e.bytesOut.Add(out)
}

// Stats is a point-in-time snapshot of one carrier.
type Stats struct {
	Path      string        `json:"path"`
	Transport string        `json:"transport"`
	Role      string        `json:"role"`
	Remote    string        `json:"remote"`
	Active    int64         `json:"active"`
	Streams   uint64        `json:"streams_total"`
	BytesIn   uint64        `json:"bytes_in"`
	BytesOut  uint64        `json:"bytes_out"`
	Failures  uint64        `json:"failures"`
	Latency   time.Duration `json:"open_latency_ns"`
	Uptime    time.Duration `json:"uptime_ns"`
}

// Set is a live collection of carriers for one logical tunnel session.
type Set struct {
	mu      sync.RWMutex
	entries []*Entry
	changed chan struct{}
	closed  bool
}

// NewSet returns an empty set.
func NewSet() *Set {
	return &Set{changed: make(chan struct{}, 1)}
}

// Add registers a carrier and starts a watcher that removes it when it dies.
func (s *Set) Add(e *Entry) {
	e.since = time.Now()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		e.Carrier.Close()
		return
	}
	s.entries = append(s.entries, e)
	s.mu.Unlock()
	s.notify()

	go func() {
		<-e.Carrier.Done()
		s.Remove(e)
	}()
}

// Remove drops a carrier from the set.
func (s *Set) Remove(e *Entry) {
	s.mu.Lock()
	for i, cur := range s.entries {
		if cur == e {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	s.notify()
}

// Len returns the number of live carriers.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// CountRole returns how many carriers can serve the given role.
func (s *Set) CountRole(want transport.Role) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, e := range s.entries {
		if roleFits(e.Role, want) {
			n++
		}
	}
	return n
}

func roleFits(have, want transport.Role) bool {
	switch want {
	case transport.RoleData:
		return have.CarriesData()
	case transport.RoleBootstrap:
		return have.CarriesControl()
	default:
		return true
	}
}

// Changed returns a channel that receives whenever the set gains or loses a
// carrier, so a supervisor can react without polling.
func (s *Set) Changed() <-chan struct{} { return s.changed }

func (s *Set) notify() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Pick chooses the carrier a new flow should use.
//
// The score is queue depth per unit of weight, scaled by how much slower this
// carrier's recent opens were than the best carrier's. A path that starts
// losing packets gets a worse score on its own, so traffic drains off it
// gradually rather than waiting for a health check to declare it dead.
func (s *Set) Pick(want transport.Role) (*Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		best     *Entry
		bestCost = math.Inf(1)
		fastest  = time.Duration(math.MaxInt64)
	)
	for _, e := range s.entries {
		if roleFits(e.Role, want) {
			if l := e.Latency(); l > 0 && l < fastest {
				fastest = l
			}
		}
	}

	for _, e := range s.entries {
		if !roleFits(e.Role, want) {
			continue
		}
		w := float64(e.Weight)
		if w <= 0 {
			w = 1
		}
		cost := (float64(e.Active()) + 1) / w
		if l := e.Latency(); l > 0 && fastest > 0 && fastest != time.Duration(math.MaxInt64) {
			cost *= float64(l) / float64(fastest)
		}
		if cost < bestCost {
			best, bestCost = e, cost
		}
	}
	if best == nil {
		return nil, ErrNoCarrier
	}
	return best, nil
}

// OpenStream picks a carrier and opens a stream on it, recording the latency
// sample and keeping the queue depth accurate for the next scheduling pass.
// The returned release function must be called exactly once, when the stream
// is finished.
func (s *Set) OpenStream(ctx context.Context, want transport.Role) (transport.Stream, *Entry, func(), error) {
	e, err := s.Pick(want)
	if err != nil {
		return nil, nil, nil, err
	}

	e.active.Add(1)
	start := time.Now()
	st, err := e.Carrier.OpenStream(ctx)
	if err != nil {
		e.active.Add(-1)
		e.failures.Add(1)
		return nil, nil, nil, err
	}
	e.observe(time.Since(start))
	e.streams.Add(1)

	var once sync.Once
	release := func() {
		once.Do(func() { e.active.Add(-1) })
	}
	return st, e, release, nil
}

// Snapshot returns per-carrier statistics, busiest first.
func (s *Set) Snapshot() []Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Stats, 0, len(s.entries))
	for _, e := range s.entries {
		remote := ""
		if a := e.Carrier.RemoteAddr(); a != nil {
			remote = a.String()
		}
		out = append(out, Stats{
			Path:      e.Path,
			Transport: e.Carrier.Transport(),
			Role:      string(e.Role),
			Remote:    remote,
			Active:    e.Active(),
			Streams:   e.streams.Load(),
			BytesIn:   e.bytesIn.Load(),
			BytesOut:  e.bytesOut.Load(),
			Failures:  e.failures.Load(),
			Latency:   e.Latency(),
			Uptime:    time.Since(e.since),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Active > out[j].Active })
	return out
}

// Close tears down every carrier and refuses further additions.
func (s *Set) Close() {
	s.mu.Lock()
	s.closed = true
	entries := s.entries
	s.entries = nil
	s.mu.Unlock()

	for _, e := range entries {
		e.Carrier.Close()
	}
	s.notify()
}
