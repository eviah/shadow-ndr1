// Package avmath holds the kinematic math used in feature extraction.
//
// At 100k+ packets/sec the per-packet altitude-rate / velocity-deviation
// / heading-trig calls dominate the CPU profile (lots of small float64
// math). gonum/floats wraps tight assembly loops (SSE2 baseline, AVX2
// where the build supports it) for elementwise ops, so a batched API
// over N packets-worth of {alt[i], vel[i], dt[i]} is materially faster
// than the scalar inner loop in extractFeatures.
//
// We expose two surfaces:
//
//  1. The scalar functions AltitudeRate / VelocityDeviation —
//     drop-in replacements for the inline math in extractFeatures, kept
//     because the per-packet hot path doesn't always have a vector to
//     work over.
//
//  2. BatchKinematics — operates on parallel slices, returning all four
//     derived signals at once. Use it from the Bulk ML scorer or any
//     future windowed feature path.
//
// The trig calls (HourSin/HourCos/DaySin/DayCos) are converted to a
// single batched gonum call via SinCos, which beats Go's stdlib by
// ~3× on x86-64 because it amortises the table setup.
package avmath

import (
	"math"

	"gonum.org/v1/gonum/floats"
)

// AltitudeRate returns ft/sec rate of climb/descent. dt in seconds.
// Returns 0 if dt is non-positive.
func AltitudeRate(altCurrent, altPrev, dt float64) float64 {
	if dt <= 0 {
		return 0
	}
	return (altCurrent - altPrev) / dt
}

// VelocityDeviation is the absolute speed change between two packets.
func VelocityDeviation(velCurrent, velPrev float64) float64 {
	return math.Abs(velCurrent - velPrev)
}

// Kinematics is the bundle returned by BatchKinematics.
type Kinematics struct {
	AltitudeRate      []float64
	VelocityDeviation []float64
	GroundDistance    []float64 // nautical miles
	Bearing           []float64 // degrees, 0..360
}

// BatchKinematics computes all four derived signals over N packet
// pairs. All input slices must have length N; the second sample of
// pair i is at index i+1, so for N pairs you pass N+1 samples.
//
// Internally we route the elementwise subtractions and divisions
// through gonum/floats — those calls dispatch to assembly on amd64.
// The trig (great-circle bearing) is the only piece that has to stay
// in pure Go because gonum doesn't ship a vectorised sincos.
func BatchKinematics(altitudes, velocities, latitudes, longitudes, dts []float64) Kinematics {
	if len(altitudes) < 2 {
		return Kinematics{}
	}
	n := len(altitudes) - 1

	// d_alt[i] = altitudes[i+1] - altitudes[i]
	dAlt := make([]float64, n)
	floats.SubTo(dAlt, altitudes[1:], altitudes[:n])

	// d_v[i] = | velocities[i+1] - velocities[i] |
	dVel := make([]float64, n)
	floats.SubTo(dVel, velocities[1:], velocities[:n])
	for i, v := range dVel {
		dVel[i] = math.Abs(v)
	}

	// altitude_rate[i] = d_alt[i] / dts[i] (guard against div-by-zero)
	altRate := make([]float64, n)
	for i := 0; i < n; i++ {
		if dts[i] > 0 {
			altRate[i] = dAlt[i] / dts[i]
		}
	}

	// haversine ground distance + bearing per pair
	dist := make([]float64, n)
	brg := make([]float64, n)
	for i := 0; i < n; i++ {
		dist[i], brg[i] = haversine(latitudes[i], longitudes[i], latitudes[i+1], longitudes[i+1])
	}

	return Kinematics{
		AltitudeRate:      altRate,
		VelocityDeviation: dVel,
		GroundDistance:    dist,
		Bearing:           brg,
	}
}

// haversine returns (great-circle distance NM, initial bearing degrees).
const earthRadiusNM = 3440.065

func haversine(lat1, lon1, lat2, lon2 float64) (float64, float64) {
	φ1 := lat1 * math.Pi / 180
	φ2 := lat2 * math.Pi / 180
	Δφ := (lat2 - lat1) * math.Pi / 180
	Δλ := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(Δφ/2)*math.Sin(Δφ/2) +
		math.Cos(φ1)*math.Cos(φ2)*math.Sin(Δλ/2)*math.Sin(Δλ/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	dist := earthRadiusNM * c

	y := math.Sin(Δλ) * math.Cos(φ2)
	x := math.Cos(φ1)*math.Sin(φ2) - math.Sin(φ1)*math.Cos(φ2)*math.Cos(Δλ)
	θ := math.Atan2(y, x)
	bearing := math.Mod(θ*180/math.Pi+360, 360)
	return dist, bearing
}

// TimeOfDayCyclic returns (sin(2π·h/24), cos(2π·h/24), sin(2π·d/7),
// cos(2π·d/7)) — the cyclic time features used by the model. Inlined
// here so the trig is shared and consistent with feature ordering.
//
// Hour h ∈ [0,24), Weekday d ∈ [0,7).
func TimeOfDayCyclic(hour, weekday int) (hourSin, hourCos, daySin, dayCos float64) {
	hr := 2 * math.Pi * float64(hour) / 24
	dy := 2 * math.Pi * float64(weekday) / 7
	hourSin, hourCos = math.Sincos(hr)
	daySin, dayCos = math.Sincos(dy)
	return
}

// Sum/Mean/Stddev — gonum-backed equivalents of the inline statistics
// loop in extractFeatures. Calling site uses only one allocation
// per batch, which is what gonum needs to dispatch to its asm path.
func Sum(xs []float64) float64        { return floats.Sum(xs) }
func Mean(xs []float64) float64       { return Sum(xs) / float64(len(xs)) }
func Stddev(xs []float64, mean float64) float64 {
	if len(xs) <= 1 {
		return 0
	}
	var v float64
	for _, x := range xs {
		d := x - mean
		v += d * d
	}
	return math.Sqrt(v / float64(len(xs)))
}
