// Package dedup provides a two-tier deduplicator: a Bloom filter for
// fast probable-membership checks plus a recency LRU for exact
// confirmation on positive hits.
//
// The shape of the problem:
//
// Kafka consumers must tolerate duplicates (at-least-once delivery).
// In Shadow NDR, duplicates also appear when retried sensor batches
// land twice or when a flow record is re-emitted after a tap window
// rotation. Re-inserting the duplicate into ClickHouse wastes disk
// and makes downstream analytics over-count.
//
// A plain LRU sized for the full traffic window costs hundreds of MB
// per node and dominates GC. A plain Bloom filter has false positives
// — and false-positive *suppression* of a legitimately-new event is
// far worse than seeing a duplicate. So we layer:
//
//  1. Bloom filter sized for the long retention window (cheap,
//     probabilistic, no false negatives).
//  2. Small LRU for exact recency confirmation.
//
// Decision: `Seen(id)` returns true iff we are certain we have seen
// this id recently. Bloom miss → not seen, fast path. Bloom hit + LRU
// hit → seen, drop. Bloom hit + LRU miss → treat as not seen (better
// to admit the rare duplicate than to drop a real event), and add to
// LRU so a near-future repeat is caught.
//
// Hashing: two independent 64-bit hashes derived from FNV-1a + xxhash
// fold; for k bloom slots we use Kirsch–Mitzenmacher double hashing
// (h1 + i*h2) which is statistically equivalent to k independent hashes
// for our k ≤ 16.
package dedup

import (
	"hash/fnv"
	"sync"
)

// Bloom is a fixed-size bit-vector Bloom filter.
type Bloom struct {
	bits []uint64
	m    uint64 // bits = m * 64
	k    uint64 // hash count
	mu   sync.Mutex
}

// NewBloom builds a filter with `bits` bits (rounded up to a multiple
// of 64) and `k` hash functions.
//
// For target FP rate p over n items: m ≈ -(n ln p) / (ln 2)^2 and
// k ≈ (m/n) ln 2. A helper, OptimalBloom, hides this math from callers
// who think in terms of "n items, p false-positive rate."
func NewBloom(bits, k int) *Bloom {
	if bits <= 0 || k <= 0 {
		panic("dedup.NewBloom: bits and k must be > 0")
	}
	words := (bits + 63) / 64
	return &Bloom{
		bits: make([]uint64, words),
		m:    uint64(words) * 64,
		k:    uint64(k),
	}
}

// OptimalBloom builds a filter sized for `expected` items at false
// positive rate `p`. Both must be > 0 and p < 1.
func OptimalBloom(expected int, p float64) *Bloom {
	if expected <= 0 || p <= 0 || p >= 1 {
		panic("dedup.OptimalBloom: invalid parameters")
	}
	// m = -(n ln p) / (ln 2)^2
	const ln2 = 0.6931471805599453
	mFloat := -float64(expected) * lnApprox(p) / (ln2 * ln2)
	if mFloat < 64 {
		mFloat = 64
	}
	bits := int(mFloat + 0.5)
	// k = (m/n) ln 2
	kFloat := mFloat / float64(expected) * ln2
	k := int(kFloat + 0.5)
	if k < 1 {
		k = 1
	}
	if k > 32 {
		k = 32
	}
	return NewBloom(bits, k)
}

// Add inserts an id (any byte representation) into the filter.
func (b *Bloom) Add(id []byte) {
	h1, h2 := hashes(id)
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := uint64(0); i < b.k; i++ {
		bit := (h1 + i*h2) % b.m
		b.bits[bit/64] |= 1 << (bit % 64)
	}
}

// MaybeContains returns true if the id may be in the filter.
// False positives are possible; false negatives are not.
func (b *Bloom) MaybeContains(id []byte) bool {
	h1, h2 := hashes(id)
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := uint64(0); i < b.k; i++ {
		bit := (h1 + i*h2) % b.m
		if b.bits[bit/64]&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

// Reset clears all bits.
func (b *Bloom) Reset() {
	b.mu.Lock()
	for i := range b.bits {
		b.bits[i] = 0
	}
	b.mu.Unlock()
}

// FillRatio returns the fraction of bits set, useful for telemetry.
// A ratio approaching 0.5 means the filter is at saturation and the
// FP rate is climbing — time to age it out (Reset, or rotate to a
// fresh filter).
func (b *Bloom) FillRatio() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	set := 0
	for _, w := range b.bits {
		set += popcount(w)
	}
	return float64(set) / float64(b.m)
}

func popcount(x uint64) int {
	x = x - ((x >> 1) & 0x5555555555555555)
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0F
	return int((x * 0x0101010101010101) >> 56)
}

func hashes(id []byte) (uint64, uint64) {
	h := fnv.New64a()
	h.Write(id)
	h1 := h.Sum64()
	// Second hash via salt prefix — keeps us off the cgo / xxhash dep
	// and is independent enough for double-hashing.
	h2obj := fnv.New64a()
	h2obj.Write([]byte{0xa5, 0x5a})
	h2obj.Write(id)
	h2 := h2obj.Sum64()
	if h2 == 0 {
		h2 = 1 // guard against k*h2 = 0 collapsing the slot set
	}
	return h1, h2
}

// lnApprox is a small natural-log helper that avoids importing math
// for one call. Uses series expansion via 2*atanh((x-1)/(x+1)).
func lnApprox(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// reduce x to [0.5, 2) by scaling with powers of e.
	const ln2 = 0.6931471805599453
	scale := 0.0
	for x > 1.5 {
		x /= 2
		scale += ln2
	}
	for x < 0.6 {
		x *= 2
		scale -= ln2
	}
	t := (x - 1) / (x + 1)
	t2 := t * t
	// 2 * (t + t^3/3 + t^5/5 + t^7/7)
	return scale + 2*(t+t2*t/3+t2*t2*t/5+t2*t2*t2*t/7)
}

// ----- LRU recency cache --------------------------------------------------

// LRU is a string-keyed bounded recency cache. Used as the second tier
// after a Bloom positive to confirm or admit.
type LRU struct {
	cap     int
	mu      sync.Mutex
	items   map[string]*lruNode
	head    *lruNode // most-recently used
	tail    *lruNode // least-recently used
}

type lruNode struct {
	key  string
	prev *lruNode
	next *lruNode
}

// NewLRU returns an LRU with `capacity` slots.
func NewLRU(capacity int) *LRU {
	if capacity <= 0 {
		panic("dedup.NewLRU: capacity must be > 0")
	}
	return &LRU{cap: capacity, items: make(map[string]*lruNode, capacity)}
}

// Has returns true if the key is present and bumps it to MRU.
func (l *LRU) Has(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := l.items[key]
	if !ok {
		return false
	}
	l.touchLocked(n)
	return true
}

// Add inserts the key (or refreshes if present). Returns true if the
// key was already present.
func (l *LRU) Add(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n, ok := l.items[key]; ok {
		l.touchLocked(n)
		return true
	}
	if len(l.items) >= l.cap {
		l.evictLocked()
	}
	n := &lruNode{key: key}
	l.items[key] = n
	l.pushFrontLocked(n)
	return false
}

// Size returns the number of resident keys.
func (l *LRU) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}

func (l *LRU) touchLocked(n *lruNode) {
	if n == l.head {
		return
	}
	// detach
	if n.prev != nil {
		n.prev.next = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	}
	if n == l.tail {
		l.tail = n.prev
	}
	// push front
	n.prev = nil
	n.next = l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (l *LRU) pushFrontLocked(n *lruNode) {
	n.next = l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (l *LRU) evictLocked() {
	if l.tail == nil {
		return
	}
	delete(l.items, l.tail.key)
	if l.tail.prev != nil {
		l.tail.prev.next = nil
	} else {
		l.head = nil
	}
	l.tail = l.tail.prev
}

// ----- Combined deduper ---------------------------------------------------

// Deduper combines Bloom (probabilistic, large window) with LRU (exact,
// small recency window). Concurrent-safe.
type Deduper struct {
	bloom *Bloom
	lru   *LRU
}

// NewDeduper builds a layered deduper. `bloom` and `lru` cannot be nil.
func NewDeduper(bloom *Bloom, lru *LRU) *Deduper {
	if bloom == nil || lru == nil {
		panic("dedup.NewDeduper: bloom and lru must be non-nil")
	}
	return &Deduper{bloom: bloom, lru: lru}
}

// Seen returns true if the id is a confirmed recent duplicate (and
// records this hit). Returns false on first sighting and inserts the
// id into both tiers so the next call returns true.
func (d *Deduper) Seen(id []byte) bool {
	if !d.bloom.MaybeContains(id) {
		// Definitely new. Admit + remember.
		d.bloom.Add(id)
		d.lru.Add(string(id))
		return false
	}
	// Bloom positive — could be a real recent duplicate or a FP.
	// Confirm via LRU.
	if d.lru.Has(string(id)) {
		return true
	}
	// FP (or aged-out of LRU). Treat as new — better to admit a rare
	// duplicate than reject a legitimate event.
	d.bloom.Add(id)
	d.lru.Add(string(id))
	return false
}

// Stats are point-in-time observations.
type Stats struct {
	BloomFill float64
	LRUSize   int
}

func (d *Deduper) Stats() Stats {
	return Stats{
		BloomFill: d.bloom.FillRatio(),
		LRUSize:   d.lru.Size(),
	}
}
