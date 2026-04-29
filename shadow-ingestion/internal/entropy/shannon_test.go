package entropy

import (
	"crypto/rand"
	"math"
	"sync"
	"testing"
	"time"
)

func TestShannonBits_Empty(t *testing.T) {
	if got := ShannonBits(nil); got != 0 {
		t.Errorf("ShannonBits(nil) = %v, want 0", got)
	}
	if got := ShannonBits([]byte{}); got != 0 {
		t.Errorf("ShannonBits([]) = %v, want 0", got)
	}
}

func TestShannonBits_SingleByteIsZero(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 0xAB
	}
	if got := ShannonBits(data); got > 1e-9 {
		t.Errorf("constant-byte entropy = %v, want ~0", got)
	}
}

func TestShannonBits_TwoEqualBytesIsOne(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		if i%2 == 0 {
			data[i] = 0
		} else {
			data[i] = 1
		}
	}
	got := ShannonBits(data)
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("alternating two-symbol entropy = %v, want 1.0", got)
	}
}

func TestShannonBits_UniformByteRangeNearMax(t *testing.T) {
	// 256 distinct bytes each appearing once → exactly H = 8.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	got := ShannonBits(data)
	if math.Abs(got-8.0) > 1e-9 {
		t.Errorf("uniform 256-byte entropy = %v, want 8.0", got)
	}
}

func TestShannonBits_RandomDataAboveSeven(t *testing.T) {
	// 8KiB of crypto-random should land >7.9 bits/byte with overwhelming
	// probability.
	data := make([]byte, 8192)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	got := ShannonBits(data)
	if got < 7.9 {
		t.Errorf("crypto/rand 8KiB entropy = %v, want >= 7.9", got)
	}
}

func TestShannonBits_PlaintextBelowSix(t *testing.T) {
	// English text typically lands around 4.0–4.7 bits/byte.
	text := []byte("the quick brown fox jumps over the lazy dog. " +
		"the quick brown fox jumps over the lazy dog. " +
		"the quick brown fox jumps over the lazy dog. " +
		"the quick brown fox jumps over the lazy dog.")
	got := ShannonBits(text)
	if got >= 6.0 {
		t.Errorf("english plaintext entropy = %v, want < 6.0", got)
	}
}

func TestNormalised_RangeAndScale(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	got := Normalised(data)
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("Normalised(uniform) = %v, want 1.0", got)
	}
	if Normalised(nil) != 0 {
		t.Error("Normalised(nil) should be 0")
	}
}

func TestWindow_FirstObservationReturnsItself(t *testing.T) {
	w := NewWindow(time.Second, 16)
	avg, ema, sd := w.Observe(FlowKey{Src: "a", Dst: "b", DstPort: 443}, 7.95)
	if math.Abs(avg-7.95) > 1e-9 {
		t.Errorf("first avg = %v, want 7.95", avg)
	}
	if math.Abs(ema-7.95) > 1e-9 {
		t.Errorf("first ema = %v, want 7.95 (initialised to first sample)", ema)
	}
	if sd != 0 {
		t.Errorf("first stddev = %v, want 0", sd)
	}
}

func TestWindow_AverageAcrossMultipleSamples(t *testing.T) {
	w := NewWindow(time.Second, 16)
	key := FlowKey{Src: "a", Dst: "b", DstPort: 80}
	for _, h := range []float64{6.0, 7.0, 8.0} {
		w.Observe(key, h)
	}
	avg, _, _ := w.Observe(key, 5.0)
	want := (6.0 + 7.0 + 8.0 + 5.0) / 4
	if math.Abs(avg-want) > 1e-9 {
		t.Errorf("avg = %v, want %v", avg, want)
	}
}

func TestWindow_EMARespondsToTrend(t *testing.T) {
	w := NewWindow(time.Second, 64)
	key := FlowKey{Src: "x", Dst: "y", DstPort: 22}
	for i := 0; i < 50; i++ {
		w.Observe(key, 4.0)
	}
	_, emaLow, _ := w.Observe(key, 4.0)
	if emaLow > 4.5 {
		t.Errorf("ema after low-entropy run = %v, want close to 4.0", emaLow)
	}
	for i := 0; i < 50; i++ {
		w.Observe(key, 7.95)
	}
	_, emaHigh, _ := w.Observe(key, 7.95)
	if emaHigh < 7.5 {
		t.Errorf("ema after high-entropy run = %v, want >= 7.5", emaHigh)
	}
}

func TestWindow_ExpiresOldSamples(t *testing.T) {
	w := NewWindow(50*time.Millisecond, 64)
	key := FlowKey{Src: "a", Dst: "b", DstPort: 1}
	w.Observe(key, 1.0)
	w.Observe(key, 1.0)
	time.Sleep(80 * time.Millisecond)
	avg, _, _ := w.Observe(key, 8.0)
	// Old 1.0 samples should have aged out, leaving avg ≈ 8.0.
	if avg < 7.5 {
		t.Errorf("avg after expiry = %v, want >= 7.5", avg)
	}
}

func TestWindow_CapacityCap(t *testing.T) {
	w := NewWindow(time.Hour, 4)
	key := FlowKey{Src: "a", Dst: "b", DstPort: 1}
	for i := 0; i < 20; i++ {
		w.Observe(key, float64(i))
	}
	avg, _, _ := w.Observe(key, 100)
	// The window holds at most Capacity=4+1 (the new one). If trim runs
	// after append, len ≤ Capacity — verify by direct inspection.
	w.mu.Lock()
	got := len(w.flows[key].samples)
	w.mu.Unlock()
	if got > 4 {
		t.Errorf("window holds %d samples, want <= 4", got)
	}
	_ = avg
}

func TestIsCovert(t *testing.T) {
	if IsCovert(7.0) {
		t.Error("ema=7.0 should not be covert")
	}
	if !IsCovert(SuspiciousEMA) {
		t.Errorf("ema=%v (threshold) should be covert", SuspiciousEMA)
	}
	if !IsCovert(7.95) {
		t.Error("ema=7.95 should be covert")
	}
}

func TestSweep_RemovesIdleFlows(t *testing.T) {
	w := NewWindow(20*time.Millisecond, 16)
	w.Observe(FlowKey{Src: "active", Dst: "x", DstPort: 1}, 5.0)
	w.Observe(FlowKey{Src: "stale", Dst: "x", DstPort: 1}, 5.0)

	time.Sleep(60 * time.Millisecond) // > 2 * Duration

	// Refresh the active flow so only the stale one ages out.
	w.Observe(FlowKey{Src: "active", Dst: "x", DstPort: 1}, 5.0)

	dropped := w.Sweep()
	if dropped != 1 {
		t.Errorf("Sweep dropped %d, want 1", dropped)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.flows[FlowKey{Src: "stale", Dst: "x", DstPort: 1}]; ok {
		t.Error("stale flow still present after sweep")
	}
	if _, ok := w.flows[FlowKey{Src: "active", Dst: "x", DstPort: 1}]; !ok {
		t.Error("active flow was wrongly evicted")
	}
}

func TestWindow_ConcurrentObserve(t *testing.T) {
	w := NewWindow(time.Second, 32)
	const goroutines = 16
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := FlowKey{Src: "a", Dst: "b", DstPort: uint16(g)}
			for i := 0; i < 1000; i++ {
				w.Observe(key, float64(i%8))
			}
		}(g)
	}
	wg.Wait()

	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.flows) != goroutines {
		t.Errorf("flows = %d, want %d", len(w.flows), goroutines)
	}
}

func BenchmarkShannonBits1KB(b *testing.B) {
	data := make([]byte, 1024)
	rand.Read(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShannonBits(data)
	}
}

func BenchmarkObserve(b *testing.B) {
	w := NewWindow(time.Second, 32)
	key := FlowKey{Src: "a", Dst: "b", DstPort: 443}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Observe(key, 7.5)
	}
}
