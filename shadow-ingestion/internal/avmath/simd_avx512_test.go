package avmath

import (
	"math"
	"testing"
)

func TestSquaredResidualBatch_MatchesScalar(t *testing.T) {
	const n = 256 // multiple of 16 to exercise the asm path
	a := make([]float32, n)
	b := make([]float32, n)
	for i := 0; i < n; i++ {
		a[i] = float32(i) * 0.5
		b[i] = float32(i)*0.5 + float32(i%7)*0.125
	}
	out := make([]float32, n)
	SquaredResidualBatch(out, a, b)

	for i := 0; i < n; i++ {
		d := a[i] - b[i]
		want := d * d
		if math.Abs(float64(out[i]-want)) > 1e-6 {
			t.Fatalf("idx %d: got %v, want %v", i, out[i], want)
		}
	}
}

func TestSquaredResidualBatch_TailIsScalar(t *testing.T) {
	// Length not a multiple of 16 — must take the scalar branch and
	// produce identical results.
	const n = 53
	a := make([]float32, n)
	b := make([]float32, n)
	for i := 0; i < n; i++ {
		a[i] = float32(i) * 0.3
		b[i] = float32(i) * 0.4
	}
	out := make([]float32, n)
	SquaredResidualBatch(out, a, b)
	for i := 0; i < n; i++ {
		d := a[i] - b[i]
		if math.Abs(float64(out[i]-d*d)) > 1e-6 {
			t.Fatalf("idx %d mismatch", i)
		}
	}
}

func TestL2NormSquared(t *testing.T) {
	a := []float32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b := []float32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	got := L2NormSquared(a, b)
	// 1+4+9+16+25+36+49+64+81+100+121+144+169+196+225+256 = 1496
	want := float32(1496)
	if math.Abs(float64(got-want)) > 1e-3 {
		t.Fatalf("L2² = %v, want %v", got, want)
	}
}

func BenchmarkSquaredResidualBatch_1024(b *testing.B) {
	const n = 1024
	a1 := make([]float32, n)
	a2 := make([]float32, n)
	out := make([]float32, n)
	for i := 0; i < n; i++ {
		a1[i] = float32(i) * 0.5
		a2[i] = float32(i) * 0.4
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SquaredResidualBatch(out, a1, a2)
	}
}
