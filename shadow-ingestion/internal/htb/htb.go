// Package htb implements a two-level hierarchical token-bucket rate
// limiter for ADS-B / network ingestion.
//
// Why hierarchical: a single sliding-window limiter on (SrcIP) lets one
// noisy aircraft eat the entire airline's budget. The HTB enforces:
//
//	per-aircraft (ICAO24) ≤ 500 pkts/sec
//	per-airline  (operator)  ≤ 5000 pkts/sec
//	global       (everything) ≤ a configurable ceiling
//
// A packet must acquire a token at every level of its hierarchy. Any
// missing level rejects → packet is rate-limited and the metric counter
// for that level increments, which makes "noisy neighbour" vs. "airline
// over its plan" vs. "we're cooked" trivially diagnosable from Grafana.
//
// Buckets are lock-amortised: only the bucket being charged takes its
// own mutex (not a global one), so per-aircraft contention is bounded
// by per-aircraft traffic. The bucket map is sharded by FNV-1a of the
// key into 32 shards to keep map mutation under control without a sync.Map.
package htb

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const numShards = 32

var (
	htbAllowed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadow_htb_allowed_total",
		Help: "Packets that successfully acquired tokens at every level.",
	})
	htbRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadow_htb_rejected_total",
		Help: "Packets rejected because a level was empty.",
	}, []string{"level"}) // level = "global" | "airline" | "aircraft"
)

// Rate config: tokens per second + burst size.
type Rate struct {
	PerSec float64
	Burst  float64
}

// Config wires up all three tiers.
type Config struct {
	Global   Rate // ceiling across every airline
	Airline  Rate // per-operator budget
	Aircraft Rate // per-ICAO24 budget
}

// DefaultConfig matches the spec from the upgrade brief:
//
//	airline  : 5000 pkts/sec
//	aircraft :  500 pkts/sec
//	global   : 50000 pkts/sec (10× airline; protects shared infra)
func DefaultConfig() Config {
	return Config{
		Global:   Rate{PerSec: 50000, Burst: 5000},
		Airline:  Rate{PerSec: 5000, Burst: 1000},
		Aircraft: Rate{PerSec: 500, Burst: 200},
	}
}

// ─── single bucket ─────────────────────────────────────────────────────────

type bucket struct {
	mu       sync.Mutex
	tokens   float64
	cap      float64
	rate     float64
	lastTick time.Time
}

func newBucket(r Rate) *bucket {
	return &bucket{
		tokens:   r.Burst,
		cap:      r.Burst,
		rate:     r.PerSec,
		lastTick: time.Now(),
	}
}

func (b *bucket) take() bool {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	dt := now.Sub(b.lastTick).Seconds()
	if dt > 0 {
		b.tokens += dt * b.rate
		if b.tokens > b.cap {
			b.tokens = b.cap
		}
		b.lastTick = now
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

// refund returns the token taken at this level. Used when a higher
// level later rejects: we don't want to penalise the lower bucket
// for traffic that never made it through anyway.
func (b *bucket) refund() {
	b.mu.Lock()
	if b.tokens+1 < b.cap {
		b.tokens++
	}
	b.mu.Unlock()
}

// ─── sharded bucket maps ───────────────────────────────────────────────────

type shard struct {
	mu      sync.RWMutex
	buckets map[string]*bucket
}

type tier struct {
	shards [numShards]*shard
	rate   Rate
}

func newTier(r Rate) *tier {
	t := &tier{rate: r}
	for i := range t.shards {
		t.shards[i] = &shard{buckets: make(map[string]*bucket)}
	}
	return t
}

func shardOf(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % numShards)
}

func (t *tier) get(key string) *bucket {
	idx := shardOf(key)
	s := t.shards[idx]
	s.mu.RLock()
	if b, ok := s.buckets[key]; ok {
		s.mu.RUnlock()
		return b
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[key]; ok {
		return b
	}
	b := newBucket(t.rate)
	s.buckets[key] = b
	return b
}

// ─── public API ────────────────────────────────────────────────────────────

// Limiter is the hierarchical limiter.
type Limiter struct {
	cfg      Config
	global   *bucket
	airlines *tier
	aircraft *tier
}

// New builds a Limiter from cfg.
func New(cfg Config) *Limiter {
	return &Limiter{
		cfg:      cfg,
		global:   newBucket(cfg.Global),
		airlines: newTier(cfg.Airline),
		aircraft: newTier(cfg.Aircraft),
	}
}

// Allow charges one token at every level. Returns true if every level
// had a token. If the airline tag is empty, the airline tier is skipped
// — the same applies to icao24. The global level is always charged.
//
// The order is: aircraft → airline → global. We charge the most specific
// level first so a runaway aircraft can't drain the airline bucket.
// On rejection at any later level, earlier levels are refunded so the
// books stay honest (this is the standard HTB "credit" behaviour).
func (l *Limiter) Allow(airline, icao24 string) bool {
	var aircraftBucket, airlineBucket *bucket

	if icao24 != "" {
		aircraftBucket = l.aircraft.get(icao24)
		if !aircraftBucket.take() {
			htbRejected.WithLabelValues("aircraft").Inc()
			return false
		}
	}

	if airline != "" {
		airlineBucket = l.airlines.get(airline)
		if !airlineBucket.take() {
			htbRejected.WithLabelValues("airline").Inc()
			if aircraftBucket != nil {
				aircraftBucket.refund()
			}
			return false
		}
	}

	if !l.global.take() {
		htbRejected.WithLabelValues("global").Inc()
		if airlineBucket != nil {
			airlineBucket.refund()
		}
		if aircraftBucket != nil {
			aircraftBucket.refund()
		}
		return false
	}

	htbAllowed.Inc()
	return true
}

// Stats returns the current token counts at every tier (best-effort,
// intended for diagnostics — the values are sampled without a global lock).
type Stats struct {
	GlobalTokens   float64
	AirlineCount   int
	AircraftCount  int
}

func (l *Limiter) Stats() Stats {
	l.global.mu.Lock()
	g := l.global.tokens
	l.global.mu.Unlock()
	var ac, al int
	for _, s := range l.airlines.shards {
		s.mu.RLock()
		al += len(s.buckets)
		s.mu.RUnlock()
	}
	for _, s := range l.aircraft.shards {
		s.mu.RLock()
		ac += len(s.buckets)
		s.mu.RUnlock()
	}
	return Stats{GlobalTokens: g, AirlineCount: al, AircraftCount: ac}
}
