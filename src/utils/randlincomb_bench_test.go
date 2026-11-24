package utils

import (
	"io"
	"testing"

	"github.com/cloudflare/circl/xof"

	"t-mldsa/src/fields"
)

// benchPRNG mirrors Round3's construction of the random-linear-comb
// stream: a fresh SHAKE128 XOF seeded from the (here, fixed) reconstructed
// seed.
func benchPRNG() io.Reader {
	rng := xof.SHAKE128.New()
	var seed [16]byte
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	_, _ = rng.Write(seed[:])
	return rng
}

func benchLutBits() (VecL[fields.F2_8], VecK[fields.F2_8]) {
	var bZ VecL[fields.F2_8]
	var bW VecK[fields.F2_8]
	for j := range bZ {
		bZ[j] = fields.F2_8(j)
	}
	for j := range bW {
		bW[j] = fields.F2_8(j + len(bZ))
	}
	return bZ, bW
}

// BenchmarkRandLinComb measures RandLinComb exactly as Round3 calls it: one
// fresh SHAKE128 draw, ToF2_128 lift, and F2_128 multiply-accumulate per
// entry, over L*N+K*N = 2048 entries (ML-DSA-44 sizes).
func BenchmarkRandLinComb(b *testing.B) {
	bZ, bW := benchLutBits()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RandLinComb(benchPRNG(), bZ, bW)
	}
}

// BenchmarkRandLinCombPRNGOnly isolates the cost of RandLinComb's
// io.ReadFull calls alone - drawing L*N+K*N 16-byte coefficients from a
// freshly seeded SHAKE128 XOF, without any field arithmetic.
func BenchmarkRandLinCombPRNGOnly(b *testing.B) {
	var buf [16]byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prng := benchPRNG()
		for j := 0; j < L*N+K*N; j++ {
			_, _ = io.ReadFull(prng, buf[:])
		}
	}
}

// BenchmarkRandLinCombArithmeticOnly isolates RandLinComb's field arithmetic
// (the ToF2_128 lift and F2_128 multiply-accumulate) from the PRNG draw, by
// reusing one fixed coefficient instead of reading fresh ones from the XOF.
// Comparing this against BenchmarkRandLinComb minus
// BenchmarkRandLinCombPRNGOnly attributes the bulk of RandLinComb's runtime
// to either the XOF squeeze or the field arithmetic.
func BenchmarkRandLinCombArithmeticOnly(b *testing.B) {
	bZ, bW := benchLutBits()
	coeff := fields.F2_128{}.FromBytes([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	var acc fields.F2_128
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc = fields.F2_128{}
		for j := range bZ {
			acc = acc.Add(bZ[j].ToF2_128().Mult(coeff))
		}
		for j := range bW {
			acc = acc.Add(bW[j].ToF2_128().Mult(coeff))
		}
	}
	_ = acc
}

// BenchmarkRandLinCombMultAddOnly further isolates ArithmeticOnly's cost by
// dropping the ToF2_128 lift too - the bits are lifted once up front, outside
// the timed loop - leaving only the F2_128 multiply-accumulate. Comparing
// this against BenchmarkRandLinCombArithmeticOnly attributes ArithmeticOnly's
// runtime between the lift and the multiply.
func BenchmarkRandLinCombMultAddOnly(b *testing.B) {
	bZ, bW := benchLutBits()
	coeff := fields.F2_128{}.FromBytes([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	var lZ [L * N]fields.F2_128
	var lW [K * N]fields.F2_128
	for j := range bZ {
		lZ[j] = bZ[j].ToF2_128()
	}
	for j := range bW {
		lW[j] = bW[j].ToF2_128()
	}

	var acc fields.F2_128
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		acc = fields.F2_128{}
		for j := range lZ {
			acc = acc.Add(lZ[j].Mult(coeff))
		}
		for j := range lW {
			acc = acc.Add(lW[j].Mult(coeff))
		}
	}
	_ = acc
}
