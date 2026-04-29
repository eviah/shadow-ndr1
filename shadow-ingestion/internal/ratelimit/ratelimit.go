// Package ratelimit provides per-key rate limiters with two algorithms:
//
//   - TokenBucket — burst-friendly. Useful for client-facing API quotas
//     where a brief burst should be allowed but the long-run average
//     stays bounded.
//   - SlidingWindow — burst-strict. Useful for "no more than N events in
//     any rolling window of D" — exactly the right shape for limiting
//     the volume of telemetry from a single sensor or tenant within a
//     short window, where a token bucket would let an attacker hammer
//     the API at 2× the rate by exploiting the burst.
//
// Both limiters are safe for concurrent use and store per-key state in
// a fixed-capacity LRU so memory does not grow unbounded with key
// cardinality. Idle keys are evicted; the next request after eviction
// re-creates the limiter with full capacity (the conservative choice —
// dropping the in-flight state is fine for ingestion, and it costs an
// extra Allow at most).
package ratelimit

import (
	"sync"
	"time"
)

// ----- TokenBucket --------------------------------------------------------

// TokenBucket is a single-key bucket. For per-key sharing use the
// PerKey wrapper.
type TokenBucket struct {
	capacity   float64       // max tokens
	refillRate float64       // tokens per second
	tokens     float64       // current
	last       time.Time     // last refill
	now        func() time.Time
	mu         sync.Mutex
}

// NewTokenBucket constructs a bucket with `capacity` peak burst and
// `refillRate` tokens per second. Both must be > 0.
func NewTokenBucket(capacity, refillRate float64) *TokenBucket {
	return newTokenBucket(capacity, refillRate, time.Now)
}

func newTokenBucket(capacity, refillRate float64, now func() time.Time) *TokenBucket {
	if capacity <= 0 || refillRate <= 0 {
		panic("ratelimit: capacity and refillRate must be > 0")
	}
	return &TokenBucket{
		capacity:   capacity,
		refillRate: refillRate,
		tokens:     capacity,
		last:       now(),
		now:        now,
	}
}

// Allow consumes one token if available. Returns true on success.
func (b *TokenBucket) Allow() bool { return b.AllowN(1) }

// AllowN consumes n tokens if available.
func (b *TokenBucket) AllowN(n float64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

// Tokens returns the current token balance (refilled to "now").
func (b *TokenBucket) Tokens() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	return b.tokens
}

func (b *TokenBucket) refill() {
	now := b.now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
}

// ----- SlidingWindow ------------------------------------------------------

// SlidingWindow allows up to `limit` events in any trailing `window`
// duration. Implementation: ring of timestamps, drop those older than
// now-window before each Allow.
//
// Memory: O(limit) per key. For limit >> 1000 the cost dominates and
// callers should switch to a counter-based approximation. For sensor
// tenant quotas (limit ~100/sec) this is the correct shape.
type SlidingWindow struct {
	limit  int
	window time.Duration
	events []time.Time // ring; head/tail tracked via len/idx
	idx    int
	count  int
	now    func() time.Time
	mu     sync.Mutex
}

// NewSlidingWindow returns a sliding-window limiter.
func NewSlidingWindow(limit int, window time.Duration) *SlidingWindow {
	return newSlidingWindow(limit, window, time.Now)
}

func newSlidingWindow(limit int, window time.Duration, now func() time.Time) *SlidingWindow {
	if limit <= 0 || window <= 0 {
		panic("ratelimit: limit and window must be > 0")
	}
	return &SlidingWindow{
		limit:  limit,
		window: window,
		events: make([]time.Time, limit),
		now:    now,
	}
}

// Allow records one event if under quota. Returns true on success.
func (s *SlidingWindow) Allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	cutoff := now.Add(-s.window)
	// Drop expired events from the tail. The ring is in chronological
	// order: the oldest is at (idx - count + limit) % limit.
	for s.count > 0 {
		oldestIdx := (s.idx - s.count + s.limit) % s.limit
		if s.events[oldestIdx].After(cutoff) {
			break
		}
		s.count--
	}
	if s.count >= s.limit {
		return false
	}
	s.events[s.idx] = now
	s.idx = (s.idx + 1) % s.limit
	s.count++
	return true
}

// Count returns the live (unexpired) event count.
func (s *SlidingWindow) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-s.window)
	for s.count > 0 {
		oldestIdx := (s.idx - s.count + s.limit) % s.limit
		if s.events[oldestIdx].After(cutoff) {
			break
		}
		s.count--
	}
	return s.count
}

// ----- PerKey -------------------------------------------------------------

// Limiter is the common interface satisfied by both algorithms. The
// PerKey container stores any value matching this shape.
type Limiter interface {
	Allow() bool
}

// PerKey caps memory by capping the number of distinct keys. Eviction
// is approximate-LRU based on a single sweep counter — exact LRU would
// add a doubly-linked list per key, and for our cardinality (sensor
// IDs, tenant IDs) it is overkill. On miss, `factory` builds a fresh
// limiter for the key.
type PerKey struct {
	factory func() Limiter
	cap     int

	mu      sync.Mutex
	entries map[string]*pkEntry
	tick    uint64
}

type pkEntry struct {
	limiter Limiter
	lastUse uint64
}

// NewPerKey constructs a key-sharded limiter. `factory` is called once
// per key seen for the first time. `capacity` bounds the number of
// distinct keys held in memory.
func NewPerKey(capacity int, factory func() Limiter) *PerKey {
	if capacity <= 0 {
		panic("ratelimit: PerKey capacity must be > 0")
	}
	return &PerKey{
		factory: factory,
		cap:     capacity,
		entries: make(map[string]*pkEntry, capacity),
	}
}

// Allow looks up (or creates) the limiter for `key` and calls Allow.
func (p *PerKey) Allow(key string) bool {
	p.mu.Lock()
	p.tick++
	tick := p.tick
	e, ok := p.entries[key]
	if !ok {
		if len(p.entries) >= p.cap {
			p.evictOne()
		}
		e = &pkEntry{limiter: p.factory()}
		p.entries[key] = e
	}
	e.lastUse = tick
	lim := e.limiter
	p.mu.Unlock()
	// Call the underlying limiter outside the per-key lock so concurrent
	// keys don't serialise on each other.
	return lim.Allow()
}

// Size returns the number of resident keys (for metrics).
func (p *PerKey) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// evictOne removes the least-recently-used entry. Caller holds p.mu.
func (p *PerKey) evictOne() {
	var (
		evictKey string
		oldest   uint64 = ^uint64(0)
	)
	for k, e := range p.entries {
		if e.lastUse < oldest {
			oldest = e.lastUse
			evictKey = k
		}
	}
	if evictKey != "" {
		delete(p.entries, evictKey)
	}
}
