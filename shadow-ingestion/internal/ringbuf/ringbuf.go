// Package ringbuf provides a bounded multi-producer single-consumer queue
// with drop-on-overflow semantics and lock-free push/pop on the fast path.
//
// Why this exists:
// The ingestion service receives bursts of sensor packets that exceed
// downstream ClickHouse write capacity for short windows. An unbounded
// channel would OOM the process; an unbuffered channel would back-pressure
// the capture path and starve the kernel ring. This buffer drops the
// oldest writes (or new writes — caller's choice via TryPush vs Push) and
// records the loss in a counter so SREs can size capacity from production
// data instead of guessing.
//
// Concurrency model:
//   - N producers may call TryPush concurrently. The slot reservation is a
//     single CAS on `head`. After a producer wins a slot it writes the
//     payload, then publishes via a per-slot sequence number (Vyukov MPMC
//     pattern, restricted to MPSC consumer for simpler semantics).
//   - Exactly ONE goroutine should call TryPop. Multi-consumer use is not
//     supported and not checked.
//
// Sizing:
// Capacity is rounded up to the next power of two so the index→slot
// mapping is a cheap mask instead of a modulo. A capacity of 0 is
// rejected (would deadlock on first push).
package ringbuf

import (
	"errors"
	"sync/atomic"
)

// ErrFull is returned by TryPush when the buffer has no free slots.
var ErrFull = errors.New("ringbuf: full")

// ErrEmpty is returned by TryPop when the buffer has no ready items.
var ErrEmpty = errors.New("ringbuf: empty")

// slot holds one element plus a sequence number used to coordinate
// producer/consumer ownership without a mutex.
//
// Sequence protocol (Vyukov):
//   - Initial state: slot[i].seq = i. Producer is allowed to write.
//   - After producer writes data and bumps seq to i+1, consumer is allowed.
//   - After consumer reads and bumps seq to i+capacity, producer is allowed
//     again (next lap).
type slot[T any] struct {
	seq  atomic.Uint64
	data T
}

// Ring is a bounded MPSC queue parameterised on element type.
type Ring[T any] struct {
	mask uint64
	cap  uint64
	head atomic.Uint64 // next producer index
	tail atomic.Uint64 // next consumer index (single writer: the consumer)

	// Counters intended for Prometheus export. Use atomic loads from
	// monitoring goroutines.
	pushed  atomic.Uint64
	popped  atomic.Uint64
	dropped atomic.Uint64

	slots []slot[T]
}

// New constructs a ring with capacity rounded up to the next power of two.
// Panics on capacity == 0 (programmer error — there is no useful zero-cap
// ring).
func New[T any](capacity int) *Ring[T] {
	if capacity <= 0 {
		panic("ringbuf.New: capacity must be > 0")
	}
	c := nextPow2(uint64(capacity))
	r := &Ring[T]{
		mask:  c - 1,
		cap:   c,
		slots: make([]slot[T], c),
	}
	for i := range r.slots {
		r.slots[i].seq.Store(uint64(i))
	}
	return r
}

// Capacity returns the rounded-up power-of-two capacity.
func (r *Ring[T]) Capacity() int { return int(r.cap) }

// TryPush attempts to enqueue v without blocking. Returns ErrFull if no
// slot is currently free. Safe for concurrent producers.
func (r *Ring[T]) TryPush(v T) error {
	for {
		head := r.head.Load()
		s := &r.slots[head&r.mask]
		seq := s.seq.Load()

		// dif < 0  → consumer hasn't drained this slot yet → buffer full
		// dif == 0 → slot is ours to claim
		// dif > 0  → another producer has already advanced past us, retry
		dif := int64(seq) - int64(head)
		switch {
		case dif == 0:
			if r.head.CompareAndSwap(head, head+1) {
				s.data = v
				s.seq.Store(head + 1)
				r.pushed.Add(1)
				return nil
			}
			// CAS failed — another producer won this slot. Retry.
		case dif < 0:
			r.dropped.Add(1)
			return ErrFull
		default:
			// stale view; spin and reload
		}
	}
}

// TryPop attempts to dequeue one element. Returns ErrEmpty if no item is
// ready. NOT safe for multiple concurrent consumers — caller must
// serialise.
func (r *Ring[T]) TryPop() (T, error) {
	var zero T
	tail := r.tail.Load()
	s := &r.slots[tail&r.mask]
	seq := s.seq.Load()

	dif := int64(seq) - int64(tail+1)
	switch {
	case dif == 0:
		// Slot has been published by a producer. Claim it.
		v := s.data
		var z T
		s.data = z // drop reference for GC
		// Single-consumer: store is fine, no CAS needed on tail.
		r.tail.Store(tail + 1)
		// Hand the slot back to producers for the next lap.
		s.seq.Store(tail + r.cap)
		r.popped.Add(1)
		return v, nil
	case dif < 0:
		return zero, ErrEmpty
	default:
		// Concurrent producer is mid-publish. Same as empty for this poll.
		return zero, ErrEmpty
	}
}

// Len returns an approximate count of pending items. Cheap but inexact
// under concurrent producers — useful for metrics, not for correctness.
func (r *Ring[T]) Len() int {
	head := r.head.Load()
	tail := r.tail.Load()
	if head < tail {
		return 0
	}
	n := head - tail
	if n > r.cap {
		return int(r.cap)
	}
	return int(n)
}

// Stats returns lifetime counters. Safe to call from any goroutine.
type Stats struct {
	Pushed  uint64
	Popped  uint64
	Dropped uint64
	Pending int
	Cap     int
}

func (r *Ring[T]) Stats() Stats {
	return Stats{
		Pushed:  r.pushed.Load(),
		Popped:  r.popped.Load(),
		Dropped: r.dropped.Load(),
		Pending: r.Len(),
		Cap:     int(r.cap),
	}
}

func nextPow2(x uint64) uint64 {
	if x <= 1 {
		return 1
	}
	x--
	x |= x >> 1
	x |= x >> 2
	x |= x >> 4
	x |= x >> 8
	x |= x >> 16
	x |= x >> 32
	return x + 1
}
