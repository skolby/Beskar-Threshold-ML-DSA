package secretsharing

import (
	"strconv"
	"t-mldsa/src/fields"
	"testing"
)

// benchSizes are (threshold, numShares) pairs with threshold held at roughly
// half of numShares, so that both dimensions grow together and neither one
// is fixed in a way that would hide a term that scales with it. numShares
// grows by 2x per step so the benchmark ratios between steps directly show
// the polynomial degree: ~2x per step is linear, ~4x is quadratic, ~8x is
// cubic.
//
// fields.ZQ (the ~2^23 ML-DSA prime field) is used instead of fields.Z157
// because Z157 only has 157 elements: PartyPoint(partyID) would collide for
// numShares beyond that, which is well within the sizes benchmarked here.
var benchSizes = []int{16, 32, 64, 128, 256, 512}

func benchName(numShares int) string {
	return strconv.Itoa(numShares)
}

// BenchmarkShare measures Share alone: O(numShares * threshold), i.e.
// quadratic when threshold scales with numShares.
func BenchmarkShare(b *testing.B) {
	var secret fields.ZQ
	secret = secret.FromUint(12345)

	for _, numShares := range benchSizes {
		threshold := numShares / 2
		b.Run(benchName(numShares), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = Share(secret, threshold, numShares)
			}
		})
	}
}

// BenchmarkNewReconstructor measures building a Reconstructor from scratch:
// O(threshold^2) to precompute the shared Lagrange denominators once, plus
// O((numShares-threshold)*threshold) to batch-evaluate the numerators at
// each of the numShares-threshold points that need coefficients - overall
// O(numShares*threshold), quadratic when threshold scales with numShares.
// This is the cost the package-level Reconstruct pays on every single call.
//
// (An earlier version of this function called delta() once per coefficient,
// each call redoing an O(threshold) product from scratch - an
// O((numShares-threshold)*threshold^2) cost, cubic in numShares. See git
// history for that version and its benchmark numbers.)
func BenchmarkNewReconstructor(b *testing.B) {
	for _, numShares := range benchSizes {
		threshold := numShares / 2
		b.Run(benchName(numShares), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = NewReconstructor[fields.ZQ](threshold, numShares)
			}
		})
	}
}

// BenchmarkReconstructorReconstruct measures Reconstruct on a Reconstructor
// built once and reused, i.e. with the Lagrange-coefficient precomputation
// factored out: O(numShares*threshold), quadratic when threshold scales with
// numShares. Compare against BenchmarkReconstruct below to see how much of
// the one-shot cost is NewReconstructor's cubic setup.
func BenchmarkReconstructorReconstruct(b *testing.B) {
	var secret fields.ZQ
	secret = secret.FromUint(67890)

	for _, numShares := range benchSizes {
		threshold := numShares / 2
		shares := Share(secret, threshold, numShares)
		r := NewReconstructor[fields.ZQ](threshold, numShares)

		b.Run(benchName(numShares), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := r.Reconstruct(shares); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReconstruct measures the convenience package-level Reconstruct,
// which builds a fresh Reconstructor on every call (see its doc comment) -
// so it pays NewReconstructor's O(numShares*threshold) setup cost on top of
// the O(numShares*threshold) reconstruction itself, tracking
// BenchmarkNewReconstructor above.
func BenchmarkReconstruct(b *testing.B) {
	var secret fields.ZQ
	secret = secret.FromUint(13579)

	for _, numShares := range benchSizes {
		threshold := numShares / 2
		shares := Share(secret, threshold, numShares)

		b.Run(benchName(numShares), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := Reconstruct(shares, threshold, numShares); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
