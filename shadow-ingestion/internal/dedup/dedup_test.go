package dedup

import (
	"fmt"
	"sync"
	"testing"
)

func TestBloom_NoFalseNegatives(t *testing.T) {
	b := NewBloom(10_000, 5)
	for i := 0; i < 1000; i++ {
		key := []byte(fmt.Sprintf("id-%d", i))
		b.Add(key)
		if !b.MaybeContains(key) {
			t.Fatalf("false negative at i=%d", i)
		}
	}
}

func TestBloom_FalsePositiveRateBelowTarget(t *testing.T) {
	const (
		n      = 5000
		target = 0.01
	)
	b := OptimalBloom(n, target)
	for i := 0; i < n; i++ {
		b.Add([]byte(fmt.Sprintf("real-%d", i)))
	}
	fp := 0
	const probes = 5000
	for i := 0; i < probes; i++ {
		if b.MaybeContains([]byte(fmt.Sprintf("nope-%d", i))) {
			fp++
		}
	}
	rate := float64(fp) / float64(probes)
	// Allow 3× headroom for hash-distribution variance with a small sample.
	if rate > 3*target {
		t.Errorf("FP rate %.4f exceeded 3x target (%.4f)", rate, 3*target)
	}
}

func TestBloom_FillRatioGrows(t *testing.T) {
	b := NewBloom(1024, 4)
	if r := b.FillRatio(); r != 0 {
		t.Fatalf("empty FillRatio = %v, want 0", r)
	}
	for i := 0; i < 100; i++ {
		b.Add([]byte(fmt.Sprintf("k-%d", i)))
	}
	if r := b.FillRatio(); r <= 0 || r >= 1 {
		t.Fatalf("FillRatio = %v, want (0,1)", r)
	}
}

func TestBloom_ResetClears(t *testing.T) {
	b := NewBloom(256, 3)
	b.Add([]byte("x"))
	if !b.MaybeContains([]byte("x")) {
		t.Fatal("missing after add")
	}
	b.Reset()
	if b.MaybeContains([]byte("x")) {
		t.Fatal("present after reset")
	}
}

func TestLRU_AddAndHas(t *testing.T) {
	l := NewLRU(3)
	l.Add("a")
	l.Add("b")
	l.Add("c")
	for _, k := range []string{"a", "b", "c"} {
		if !l.Has(k) {
			t.Errorf("missing %q", k)
		}
	}
	if l.Size() != 3 {
		t.Errorf("Size = %d, want 3", l.Size())
	}
}

func TestLRU_EvictsLeastRecentlyUsed(t *testing.T) {
	l := NewLRU(3)
	l.Add("a")
	l.Add("b")
	l.Add("c")
	// Touch a → b becomes LRU.
	if !l.Has("a") {
		t.Fatal("expected a present")
	}
	l.Add("d") // evicts b
	if l.Has("b") {
		t.Error("b should have been evicted")
	}
	if !l.Has("a") || !l.Has("c") || !l.Has("d") {
		t.Error("a, c, or d missing")
	}
}

func TestLRU_RefreshOnReadd(t *testing.T) {
	l := NewLRU(2)
	l.Add("a")
	l.Add("b")
	if existed := l.Add("a"); !existed {
		t.Errorf("re-add of a should report existed=true")
	}
	l.Add("c") // should evict b, not a
	if l.Has("b") {
		t.Error("b should be evicted")
	}
	if !l.Has("a") {
		t.Error("a should remain")
	}
}

func TestDeduper_FirstSightingIsNew(t *testing.T) {
	d := NewDeduper(NewBloom(4096, 4), NewLRU(256))
	for i := 0; i < 100; i++ {
		id := []byte(fmt.Sprintf("evt-%d", i))
		if d.Seen(id) {
			t.Errorf("evt %d reported as seen on first sighting", i)
		}
	}
}

func TestDeduper_RepeatedHitsDetected(t *testing.T) {
	d := NewDeduper(NewBloom(4096, 4), NewLRU(256))
	id := []byte("repeating-id-42")
	if d.Seen(id) {
		t.Fatal("first sighting should be new")
	}
	for i := 0; i < 50; i++ {
		if !d.Seen(id) {
			t.Fatalf("repeat %d not detected", i)
		}
	}
}

func TestDeduper_LRUEvictionAdmitsAfterDelay(t *testing.T) {
	// Tiny LRU forces eviction; a duplicate is admitted (false → counts
	// as new) once the entry rolls off.
	d := NewDeduper(NewBloom(8192, 4), NewLRU(2))
	target := []byte("target")
	d.Seen(target)
	// Push 5 fresh ids — evicts target from LRU.
	for i := 0; i < 5; i++ {
		d.Seen([]byte(fmt.Sprintf("filler-%d", i)))
	}
	// Bloom still says yes (no FN); LRU says no (evicted) → treated as new.
	if d.Seen(target) {
		t.Fatal("expected target to be admitted after LRU eviction")
	}
}

func TestDeduper_Concurrent(t *testing.T) {
	d := NewDeduper(NewBloom(1<<16, 6), NewLRU(4096))
	const (
		goroutines = 8
		each       = 1000
	)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				id := []byte(fmt.Sprintf("g%d-i%d", g, i))
				d.Seen(id)
				d.Seen(id) // repeat
			}
		}(g)
	}
	wg.Wait()
	st := d.Stats()
	if st.LRUSize == 0 {
		t.Error("LRU stayed empty")
	}
	if st.BloomFill <= 0 {
		t.Error("Bloom stayed empty")
	}
}
