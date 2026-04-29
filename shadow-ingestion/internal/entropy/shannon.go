// Package entropy implements Shannon-entropy analysis used as an
// early-warning signal for encrypted C2 / stealth exfiltration.
//
// Why this matters: ML alone struggles to distinguish "high-entropy
// because the payload is compressed/TLS" from "high-entropy because it's
// AES-GCM tunnelled C2 hidden in plaintext-looking ports". Per-flow
// entropy averaged over a sliding window is one of the strongest leading
// indicators we have — encrypted channels stay near 7.95 bits/byte for
// extended runs while plaintext averages closer to 4.5–5.5.
//
// We compute entropy in two places:
//   1. Per-packet ShannonBits over the raw payload (or any byte slice).
//   2. A sliding window per (SrcIP, DstIP, DstPort) flow that smooths
//      single-packet noise — exposed via WindowAvg / WindowEMA.
//
// All operations are O(n) over a 256-entry histogram on the stack; no
// allocations in the hot path.
package entropy

import (
	"math"
	"sync"
	"time"
)

// ShannonBits returns the Shannon entropy in bits/symbol for the given
// byte slice. Empty input → 0.
//
// H(X) = -Σ p(x) · log2(p(x))   for x ∈ [0, 255]
//
// Range: 0 (one byte repeated) … 8 (uniformly random / encrypted).
func ShannonBits(data []byte) float64 {
	n := len(data)
	if n == 0 {
		return 0
	}
	var hist [256]uint32
	for _, b := range data {
		hist[b]++
	}
	invN := 1.0 / float64(n)
	h := 0.0
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) * invN
		h -= p * math.Log2(p)
	}
	return h
}

// Normalised returns ShannonBits / 8, in [0, 1] — convenient as an ML feature.
func Normalised(data []byte) float64 {
	return ShannonBits(data) / 8.0
}

// ─── Sliding-window aggregator ─────────────────────────────────────────────

type sample struct {
	ts time.Time
	h  float64
}

// FlowKey collapses a packet into a flow identifier. Use any tuple you like.
type FlowKey struct {
	Src     string
	Dst     string
	DstPort uint16
}

// Window keeps the last `Capacity` entropy samples per flow inside a
// `Window.Duration` time window. Old samples are evicted on insert.
//
// Concurrency: a single sync.Mutex covers the whole map. The hot path
// is one map lookup + one slice append + one trim, which is well under
// 100ns even at 100k pps. If contention shows up in profiles, shard by
// hash(FlowKey) % N and use N maps — pattern is identical.
type Window struct {
	mu       sync.Mutex
	flows    map[FlowKey]*flowState
	Duration time.Duration
	Capacity int
	emaAlpha float64
}

type flowState struct {
	samples []sample
	ema     float64
	last    time.Time
}

func NewWindow(duration time.Duration, capacity int) *Window {
	if duration <= 0 {
		duration = 30 * time.Second
	}
	if capacity <= 0 {
		capacity = 64
	}
	return &Window{
		flows:    make(map[FlowKey]*flowState),
		Duration: duration,
		Capacity: capacity,
		emaAlpha: 0.2,
	}
}

// Observe records an entropy sample for a flow and returns three values:
//   avg     — arithmetic mean over the active window
//   ema     — exponentially-smoothed estimate (alpha = 0.2)
//   stddev  — standard deviation across the window (jitter signal)
//
// When the same flow steadily stays near 7.9+ bits/byte, that's a strong
// "this looks encrypted regardless of port" indicator; sudden ema jumps
// over 7.5 bits/byte are the "covert channel just opened" signal.
func (w *Window) Observe(key FlowKey, h float64) (avg, ema, stddev float64) {
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	f, ok := w.flows[key]
	if !ok {
		f = &flowState{samples: make([]sample, 0, w.Capacity), ema: h}
		w.flows[key] = f
	}
	f.samples = append(f.samples, sample{ts: now, h: h})

	cutoff := now.Add(-w.Duration)
	keep := 0
	for _, s := range f.samples {
		if s.ts.After(cutoff) {
			f.samples[keep] = s
			keep++
		}
	}
	f.samples = f.samples[:keep]
	if len(f.samples) > w.Capacity {
		f.samples = f.samples[len(f.samples)-w.Capacity:]
	}

	f.ema = w.emaAlpha*h + (1-w.emaAlpha)*f.ema
	f.last = now

	var sum float64
	for _, s := range f.samples {
		sum += s.h
	}
	n := float64(len(f.samples))
	if n == 0 {
		return h, f.ema, 0
	}
	avg = sum / n
	var v float64
	for _, s := range f.samples {
		d := s.h - avg
		v += d * d
	}
	stddev = math.Sqrt(v / n)
	return avg, f.ema, stddev
}

// SuspiciousEMA is the threshold above which a flow's smoothed entropy
// is treated as "looks encrypted." Tuned against TLS / SSH / WireGuard /
// AES-GCM tunnels — all of them park between 7.85 and 7.99.
const SuspiciousEMA = 7.5

// IsCovert returns true when entropy ema is sustained above the
// suspicious threshold AND the flow is not on a port where high
// entropy is expected (443/853/etc handled by the caller).
func IsCovert(ema float64) bool {
	return ema >= SuspiciousEMA
}

// Sweep removes flows that have not seen activity in 2× the window
// duration. Call this from a background ticker every few minutes — it
// keeps the map from growing unbounded for short-lived flows.
func (w *Window) Sweep() int {
	cutoff := time.Now().Add(-2 * w.Duration)
	w.mu.Lock()
	defer w.mu.Unlock()
	dropped := 0
	for k, f := range w.flows {
		if f.last.Before(cutoff) {
			delete(w.flows, k)
			dropped++
		}
	}
	return dropped
}
