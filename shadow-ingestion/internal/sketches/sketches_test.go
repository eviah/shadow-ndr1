package sketches

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

func TestCountMin_NoUnderCounts(t *testing.T) {
	cm := NewCountMin(5, 1024)
	for i := 0; i < 1000; i++ {
		cm.Add([]byte(fmt.Sprintf("key-%d", i%100)), 1)
	}
	// Each of the 100 keys was added exactly 10 times.
	for i := 0; i < 100; i++ {
		got := cm.Estimate([]byte(fmt.Sprintf("key-%d", i)))
		if got < 10 {
			t.Errorf("key-%d estimate = %d, want >= 10 (no under-count)", i, got)
		}
	}
}

func TestCountMin_TotalTracksAdditions(t *testing.T) {
	cm := NewCountMin(3, 256)
	cm.Add([]byte("a"), 5)
	cm.Add([]byte("b"), 7)
	cm.Add([]byte("c"), 3)
	if got := cm.Total(); got != 15 {
		t.Errorf("Total = %d, want 15", got)
	}
}

func TestCountMin_AccuracyOnSkewedDistribution(t *testing.T) {
	// Heavy hitters appear 1000x; rest only once.
	d, w := Optimal(0.001, 0.01)
	cm := NewCountMin(d, w)
	heavy := []string{"alpha", "beta", "gamma"}
	for _, k := range heavy {
		for i := 0; i < 1000; i++ {
			cm.Add([]byte(k), 1)
		}
	}
	for i := 0; i < 50_000; i++ {
		cm.Add([]byte(fmt.Sprintf("rare-%d", i)), 1)
	}
	for _, k := range heavy {
		got := cm.Estimate([]byte(k))
		// At ε=0.001 over total ~53k, error ≤ 53. So estimate ∈ [1000, 1053].
		if got < 1000 || got > 1100 {
			t.Errorf("%q estimate = %d, want in [1000,1100]", k, got)
		}
	}
}

func TestCountMin_Reset(t *testing.T) {
	cm := NewCountMin(3, 64)
	cm.Add([]byte("x"), 100)
	cm.Reset()
	if got := cm.Estimate([]byte("x")); got != 0 {
		t.Errorf("after reset, estimate = %d, want 0", got)
	}
	if got := cm.Total(); got != 0 {
		t.Errorf("after reset, total = %d, want 0", got)
	}
}

func TestOptimal_SaneDimensions(t *testing.T) {
	d, w := Optimal(0.001, 0.01)
	if d < 1 || w < 100 {
		t.Errorf("Optimal(0.001,0.01) = (d=%d,w=%d), want d>=1 w>=100", d, w)
	}
}

func TestTopK_TracksHeaviest(t *testing.T) {
	cm := NewCountMin(5, 1024)
	tk := NewTopK(3, cm)

	// Stream: a appears 100x, b 200x, c 50x, d 300x, e 10x.
	emit := func(k string, n int) {
		for i := 0; i < n; i++ {
			tk.Observe([]byte(k))
		}
	}
	emit("a", 100)
	emit("b", 200)
	emit("c", 50)
	emit("d", 300)
	emit("e", 10)

	snap := tk.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d, want 3", len(snap))
	}
	want := map[string]bool{"d": true, "b": true, "a": true}
	for _, h := range snap {
		if !want[h.Key] {
			t.Errorf("unexpected top-K member: %q", h.Key)
		}
	}
	if snap[0].Key != "d" {
		t.Errorf("top-1 = %q, want d", snap[0].Key)
	}
}

func TestTopK_StableUnderRandomStream(t *testing.T) {
	cm := NewCountMin(5, 4096)
	tk := NewTopK(5, cm)

	// 95% rare keys, 5% from a hot set of 5.
	hot := []string{"H1", "H2", "H3", "H4", "H5"}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 50_000; i++ {
		if rng.Intn(20) == 0 {
			tk.Observe([]byte(hot[rng.Intn(len(hot))]))
		} else {
			tk.Observe([]byte(fmt.Sprintf("rare-%d", rng.Intn(40_000))))
		}
	}

	snap := tk.Snapshot()
	hotSet := map[string]bool{}
	for _, h := range hot {
		hotSet[h] = true
	}
	matched := 0
	for _, h := range snap {
		if hotSet[h.Key] {
			matched++
		}
	}
	// All 5 hot keys must surface — they each have ~500 hits vs at most
	// 1 each for rare keys.
	if matched < 5 {
		t.Errorf("hot keys recovered = %d, want 5; snap=%v", matched, snap)
	}
}

func TestTopK_HandlesFewerThanK(t *testing.T) {
	cm := NewCountMin(3, 256)
	tk := NewTopK(10, cm)
	tk.Observe([]byte("only"))
	if tk.Size() != 1 {
		t.Errorf("size = %d, want 1", tk.Size())
	}
}

func TestTopK_Concurrent(t *testing.T) {
	cm := NewCountMin(5, 4096)
	tk := NewTopK(8, cm)

	const goroutines = 8
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5_000; i++ {
				if i%50 == 0 {
					// Inject a hot key every 50 ops.
					tk.Observe([]byte("HOT"))
				} else {
					tk.Observe([]byte(fmt.Sprintf("g%d-%d", g, i)))
				}
			}
		}(g)
	}
	wg.Wait()

	snap := tk.Snapshot()
	if len(snap) == 0 {
		t.Fatal("snapshot empty")
	}
	if snap[0].Key != "HOT" {
		t.Errorf("top-1 = %q, want HOT", snap[0].Key)
	}
}

func BenchmarkCountMinAdd(b *testing.B) {
	cm := NewCountMin(5, 4096)
	key := []byte("benchmark-key-typical-length")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm.Add(key, 1)
	}
}

func BenchmarkTopKObserve(b *testing.B) {
	cm := NewCountMin(5, 4096)
	tk := NewTopK(100, cm)
	keys := make([][]byte, 1000)
	for i := range keys {
		keys[i] = []byte(fmt.Sprintf("k-%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tk.Observe(keys[i%len(keys)])
	}
}
