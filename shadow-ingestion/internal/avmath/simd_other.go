// Pure-Go fallback for non-amd64 builds (arm64, etc.).

//go:build !amd64

package avmath

// HasAVX512 is always false on non-amd64.
var HasAVX512 = false

// SquaredResidualBatch — scalar implementation. Same contract as the amd64
// version: out[i] = (a[i] - b[i])^2.
func SquaredResidualBatch(out, a, b []float32) {
	n := len(out)
	if n > len(a) {
		n = len(a)
	}
	if n > len(b) {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		d := a[i] - b[i]
		out[i] = d * d
	}
}

// L2NormSquared returns the sum of squared element-wise residuals.
func L2NormSquared(a, b []float32) float32 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	var s float32
	for i := 0; i < n; i++ {
		d := a[i] - b[i]
		s += d * d
	}
	return s
}
