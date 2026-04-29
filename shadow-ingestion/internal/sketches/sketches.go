// Package sketches provides streaming summaries used by the ingestion
// pipeline to keep cardinality bounded:
//
//   - CountMin: probabilistic frequency estimator (Cormode & Muthukrishnan).
//     For any key, returns an estimate that is never an under-count and
//     overshoots by at most ε * total with probability ≥ 1-δ. Memory is
//     O((1/ε) * log(1/δ)) bytes regardless of key cardinality.
//
//   - TopK: heavy-hitter heap maintained alongside a CountMin sketch.
//     Only the K most-frequent keys are kept by exact identity; their
//     counts come from the sketch (so cold keys never enter, but a hot
//     key's count is accurate to within sketch error).
//
// Use cases in Shadow NDR:
//   - "Which 100 source IPs are flooding the ingest pipeline right now?"
//     in a single bounded structure instead of a per-IP map that grows
//     to 16 M entries during a scan.
//   - "How many flows did this tenant produce in the last minute?" for
//     billing-grade ApproxCounts feeding into ClickHouse rollups.
//
// Notes:
//   - CountMin is conservative-update only on heavy-hitter ingest paths
//     where bias matters; here we use plain update because the heavy
//     hitter heap already absorbs exact tracking for what matters.
//   - Hashing uses FNV-1a with two seeds + double-hashing to materialise
//     d hash functions cheaply without cgo.
package sketches

import (
	"container/heap"
	"hash/fnv"
	"math"
	"sync"
)

// CountMin is a count-min sketch with d rows and w columns. Update and
// Estimate are O(d). Concurrent calls are serialised by mu — for
// extreme throughput, callers can shard the sketch by key hash.
type CountMin struct {
	d, w  int
	table [][]uint64
	mu    sync.Mutex
	total uint64
}

// NewCountMin builds a sketch with given d (depth, hash count) and
// w (width, columns per row). Both must be > 0.
//
// Rule of thumb: w = ceil(e / ε), d = ceil(ln(1/δ)). For ε=0.001 and
// δ=0.01, that's w=2719, d=5 → ~110 KB. The helper Optimal() does the
// math for callers.
func NewCountMin(d, w int) *CountMin {
	if d <= 0 || w <= 0 {
		panic("sketches.NewCountMin: d and w must be > 0")
	}
	tbl := make([][]uint64, d)
	for i := range tbl {
		tbl[i] = make([]uint64, w)
	}
	return &CountMin{d: d, w: w, table: tbl}
}

// Optimal returns dimensions for target additive error ε * total with
// probability ≥ 1 - δ.
func Optimal(epsilon, delta float64) (d, w int) {
	if epsilon <= 0 || epsilon >= 1 || delta <= 0 || delta >= 1 {
		panic("sketches.Optimal: epsilon, delta must be in (0,1)")
	}
	w = int(math.Ceil(math.E / epsilon))
	d = int(math.Ceil(math.Log(1 / delta)))
	if d < 1 {
		d = 1
	}
	if w < 1 {
		w = 1
	}
	return d, w
}

// Add increments the count for `key` by `delta`.
func (c *CountMin) Add(key []byte, delta uint64) {
	if delta == 0 {
		return
	}
	h1, h2 := hashes(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += delta
	for i := 0; i < c.d; i++ {
		col := (h1 + uint64(i)*h2) % uint64(c.w)
		c.table[i][col] += delta
	}
}

// Estimate returns the upper-bound count for `key`. Never under-counts;
// over-counts by at most ε * total with probability ≥ 1 - δ.
func (c *CountMin) Estimate(key []byte) uint64 {
	h1, h2 := hashes(key)
	c.mu.Lock()
	defer c.mu.Unlock()
	var min uint64 = math.MaxUint64
	for i := 0; i < c.d; i++ {
		col := (h1 + uint64(i)*h2) % uint64(c.w)
		v := c.table[i][col]
		if v < min {
			min = v
		}
	}
	return min
}

// Total returns the sum of all increments seen.
func (c *CountMin) Total() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// Reset zeroes the sketch. Useful for periodic decay (rotate every N
// minutes, query the previous epoch for stable top-K).
func (c *CountMin) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.table {
		for j := range c.table[i] {
			c.table[i][j] = 0
		}
	}
	c.total = 0
}

// ----- Top-K heavy hitters ------------------------------------------------

// TopK tracks the K most frequent keys by exact identity, with counts
// supplied by an internal CountMin sketch. New keys whose estimate
// exceeds the smallest tracked key's estimate replace it.
//
// This is a deterministic implementation of the "Misra-Gries with
// support" pattern: heavy hitters that survive across the stream are
// exactly the ones tracked here, and their counts are accurate to
// within sketch error.
type TopK struct {
	k     int
	cm    *CountMin
	heap  *minHeap
	index map[string]*topKItem
	mu    sync.Mutex
}

type topKItem struct {
	key   string
	count uint64
	idx   int // heap index
}

// NewTopK returns a TopK tracker. `k` is the number of heavy hitters
// to retain; `cm` is the underlying CountMin (callers can size it
// independently per their accuracy budget).
func NewTopK(k int, cm *CountMin) *TopK {
	if k <= 0 {
		panic("sketches.NewTopK: k must be > 0")
	}
	if cm == nil {
		panic("sketches.NewTopK: cm must be non-nil")
	}
	h := &minHeap{}
	heap.Init(h)
	return &TopK{
		k:     k,
		cm:    cm,
		heap:  h,
		index: make(map[string]*topKItem, k),
	}
}

// Observe records an occurrence and updates Top-K membership.
func (t *TopK) Observe(key []byte) {
	t.cm.Add(key, 1)
	estimate := t.cm.Estimate(key)
	t.mu.Lock()
	defer t.mu.Unlock()

	skey := string(key) // immutable copy for the map key
	if it, ok := t.index[skey]; ok {
		it.count = estimate
		heap.Fix(t.heap, it.idx)
		return
	}
	if t.heap.Len() < t.k {
		it := &topKItem{key: skey, count: estimate}
		heap.Push(t.heap, it)
		t.index[skey] = it
		return
	}
	// Replace the min if this estimate beats it.
	min := (*t.heap)[0]
	if estimate > min.count {
		delete(t.index, min.key)
		min.key = skey
		min.count = estimate
		t.index[skey] = min
		heap.Fix(t.heap, 0)
	}
}

// Snapshot returns the current top-K, sorted by count descending.
type Hitter struct {
	Key   string
	Count uint64
}

func (t *TopK) Snapshot() []Hitter {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Hitter, 0, t.heap.Len())
	for _, it := range *t.heap {
		out = append(out, Hitter{Key: it.key, Count: it.count})
	}
	// sort descending — small list, simple insertion sort.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Count < out[j].Count; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Size returns the number of tracked keys (≤ k).
func (t *TopK) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.heap.Len()
}

// minHeap is a heap.Interface ordered by count ascending, so the root
// is the easiest to evict.
type minHeap []*topKItem

func (h minHeap) Len() int           { return len(h) }
func (h minHeap) Less(i, j int) bool { return h[i].count < h[j].count }
func (h minHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx = i
	h[j].idx = j
}
func (h *minHeap) Push(x any) {
	it := x.(*topKItem)
	it.idx = len(*h)
	*h = append(*h, it)
}
func (h *minHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	x.idx = -1
	return x
}

func hashes(b []byte) (uint64, uint64) {
	h1 := fnv.New64a()
	h1.Write(b)
	a := h1.Sum64()

	h2 := fnv.New64a()
	h2.Write([]byte{0xa5, 0x5a, 0xa5, 0x5a})
	h2.Write(b)
	c := h2.Sum64()
	if c == 0 {
		c = 1
	}
	return a, c
}
