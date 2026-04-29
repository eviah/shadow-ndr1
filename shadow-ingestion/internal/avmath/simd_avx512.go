// AVX-512 kinematic SIMD entry points.
//
// These functions vectorize the inner residual loop used to score real-time
// trajectory deviations against a Kalman-predicted state vector. The work
// done per packet (16 floats of subtract/multiply per pair) is too small for
// gonum to amortize, so we drop into 16-lane ZMM math directly.
//
// Layout — `a` and `b` are flat float32 slices of length n (a multiple of
// 16). For trajectory residuals you pack [px,py,pz,vx,vy,vz, ...] for
// each tracked entity. `out[i] = (a[i]-b[i])^2`. Sum reduction lives in
// caller code (one MAC over a 16-lane register fits a single VFMADD231PS).
//
// At runtime we test for AVX-512F via golang.org/x/sys/cpu. Without it,
// SquaredResidualBatch dispatches to the scalar fallback so this file is
// safe to ship on AVX-2-only hardware (most Israeli ground-station boxes
// today). With GOAMD64=v4 builds, the asm path runs unconditionally.

//go:build amd64

package avmath

import "golang.org/x/sys/cpu"

// HasAVX512 reflects runtime detection. Exposed for tests / metrics.
var HasAVX512 = cpu.X86.HasAVX512F && cpu.X86.HasAVX512DQ

// squaredResidualAVX512 is implemented in simd_avx512_amd64.s.
//
//go:noescape
func squaredResidualAVX512(out, a, b *float32, n uintptr)

// SquaredResidualBatch computes out[i] = (a[i] - b[i])^2 for all i in [0,n).
// All slices must have length >= n. Preconditions in the AVX-512 path:
// n must be a multiple of 16 and pointers must be 4-byte aligned (Go float32
// slices satisfy this). For non-multiples of 16, callers should round n down
// and handle the tail in scalar code.
func SquaredResidualBatch(out, a, b []float32) {
	n := len(out)
	if n > len(a) {
		n = len(a)
	}
	if n > len(b) {
		n = len(b)
	}
	if n == 0 {
		return
	}
	if HasAVX512 && n%16 == 0 {
		squaredResidualAVX512(&out[0], &a[0], &b[0], uintptr(n))
		return
	}
	for i := 0; i < n; i++ {
		d := a[i] - b[i]
		out[i] = d * d
	}
}

// L2NormSquared returns the sum of squared residuals over the slice. With
// AVX-512 enabled, it pairs naturally with squaredResidualAVX512: producer
// fills `tmp`, consumer reduces with floats.Sum (asm-backed).
func L2NormSquared(a, b []float32) float32 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	tmp := make([]float32, n)
	SquaredResidualBatch(tmp, a, b)
	var s float32
	for _, v := range tmp {
		s += v
	}
	return s
}
