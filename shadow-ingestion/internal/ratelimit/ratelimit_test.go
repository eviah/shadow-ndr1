package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock supports deterministic timing for refill/window tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func TestTokenBucket_AllowsUpToCapacity(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	b := newTokenBucket(5, 1, clock.Now)
	for i := 0; i < 5; i++ {
		if !b.Allow() {
			t.Fatalf("Allow %d denied, want allowed", i)
		}
	}
	if b.Allow() {
		t.Fatalf("6th Allow should be denied")
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	b := newTokenBucket(2, 2, clock.Now) // 2 tokens/sec
	if !b.Allow() || !b.Allow() {
		t.Fatal("initial 2 allows failed")
	}
	if b.Allow() {
		t.Fatal("3rd allow at t=0 should fail")
	}
	clock.Advance(500 * time.Millisecond) // +1 token
	if !b.Allow() {
		t.Fatal("after 500ms with refill=2/s, 1 token expected")
	}
	if b.Allow() {
		t.Fatal("immediate 2nd allow after refill should fail")
	}
}

func TestTokenBucket_CappedAtCapacity(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	b := newTokenBucket(3, 100, clock.Now)
	clock.Advance(1 * time.Hour) // would refill way past capacity
	if got := b.Tokens(); got != 3 {
		t.Errorf("Tokens = %v, want 3 (cap)", got)
	}
}

func TestTokenBucket_AllowN(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	b := newTokenBucket(10, 1, clock.Now)
	if !b.AllowN(7) {
		t.Fatal("AllowN(7) on 10-cap bucket failed")
	}
	if b.AllowN(4) {
		t.Fatal("AllowN(4) on 3-token bucket should fail")
	}
	if !b.AllowN(3) {
		t.Fatal("AllowN(3) on 3-token bucket should succeed")
	}
}

func TestSlidingWindow_LimitWithinWindow(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	w := newSlidingWindow(3, time.Second, clock.Now)

	for i := 0; i < 3; i++ {
		if !w.Allow() {
			t.Fatalf("Allow %d denied, want allowed", i)
		}
	}
	if w.Allow() {
		t.Fatal("4th Allow within 1s should be denied")
	}
}

func TestSlidingWindow_ExpiresOldEvents(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	w := newSlidingWindow(2, time.Second, clock.Now)

	w.Allow() // t=0
	w.Allow() // t=0
	if w.Allow() {
		t.Fatal("3rd at t=0 should be denied")
	}

	clock.Advance(1100 * time.Millisecond) // both events older than 1s
	if !w.Allow() {
		t.Fatal("after window slide, allow should succeed")
	}
	if !w.Allow() {
		t.Fatal("after window slide, 2nd allow should succeed")
	}
	if w.Allow() {
		t.Fatal("3rd allow after slide should fail (window full again)")
	}
}

func TestSlidingWindow_RingReuse(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	w := newSlidingWindow(4, time.Second, clock.Now)

	for lap := 0; lap < 5; lap++ {
		for i := 0; i < 4; i++ {
			if !w.Allow() {
				t.Fatalf("lap %d evt %d denied", lap, i)
			}
		}
		if w.Allow() {
			t.Fatalf("lap %d 5th evt should be denied", lap)
		}
		clock.Advance(2 * time.Second)
	}
}

func TestPerKey_IsolatesKeys(t *testing.T) {
	pk := NewPerKey(10, func() Limiter {
		return NewTokenBucket(2, 0.001) // tiny refill so test is determinstic
	})
	for i := 0; i < 2; i++ {
		if !pk.Allow("alice") {
			t.Fatalf("alice %d denied", i)
		}
		if !pk.Allow("bob") {
			t.Fatalf("bob %d denied", i)
		}
	}
	if pk.Allow("alice") {
		t.Fatal("alice 3rd should be denied")
	}
	if pk.Allow("bob") {
		t.Fatal("bob 3rd should be denied")
	}
}

func TestPerKey_EvictsLRU(t *testing.T) {
	pk := NewPerKey(2, func() Limiter {
		return NewTokenBucket(1, 0.001)
	})
	pk.Allow("a")
	pk.Allow("b")
	pk.Allow("a") // touch a → b is now LRU
	pk.Allow("c") // forces eviction of b
	if pk.Size() != 2 {
		t.Fatalf("Size = %d, want 2", pk.Size())
	}

	// Both a and c should still be in their post-allow state (denied).
	// b was evicted, so a fresh bucket is created and Allow succeeds.
	if pk.Allow("a") {
		t.Error("a should be denied (still cached)")
	}
	if !pk.Allow("b") {
		t.Error("b should be allowed (evicted then recreated)")
	}
}

func TestPerKey_Concurrent(t *testing.T) {
	pk := NewPerKey(1024, func() Limiter {
		return NewTokenBucket(1000, 1000)
	})
	const (
		goroutines = 16
		perG       = 1000
	)
	allowed := atomic.Int64{}
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				if pk.Allow("k" + string(rune('A'+g%8))) {
					allowed.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	if allowed.Load() == 0 {
		t.Fatal("no requests allowed under concurrent load")
	}
	if pk.Size() == 0 {
		t.Fatal("no keys retained")
	}
}
