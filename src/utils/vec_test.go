package utils

import (
	"bytes"
	"crypto/rand"
	"testing"

	"t-mldsa/src/fields"
)

// TestCanonicalizeChallengeMatchesConversionRoundTrip checks
// CanonicalizeChallenge's constant-time three-way mapping against actually
// calling fields.ConvertSmallToZ157 followed by fields.ConvertZ157ToZQ on
// every coefficient - the general-purpose conversion CanonicalizeChallenge
// is a shortcut for, given the challenge is always ternary.
func TestCanonicalizeChallengeMatchesConversionRoundTrip(t *testing.T) {
	var c [N]uint32
	for i := range c {
		switch i % 3 {
		case 0:
			c[i] = 0
		case 1:
			c[i] = 1
		case 2:
			c[i] = fields.Q - 1 // -1
		}
	}

	got := CanonicalizeChallenge(c)
	for i, x := range c {
		want := uint32(fields.ConvertZ157ToZQ(fields.ConvertSmallToZ157(fields.ZQ(x))))
		if got[i] != want {
			t.Fatalf("coefficient %d: CanonicalizeChallenge(%d) = %d, want %d (via ConvertSmallToZ157/ConvertZ157ToZQ)", i, x, got[i], want)
		}
	}
}

// TestCanonicalizeChallengeMapsMinusOneTo156 pins down the one nontrivial
// case: Q-1 (i.e. -1) must come back as 156, Z157's representative for -1,
// lifted into ZQ - not as Q-1 itself.
func TestCanonicalizeChallengeMapsMinusOneTo156(t *testing.T) {
	var c [N]uint32
	c[0] = fields.Q - 1

	got := CanonicalizeChallenge(c)
	if got[0] != 156 {
		t.Fatalf("CanonicalizeChallenge(Q-1) = %d, want 156", got[0])
	}
}

// TestConvertVecLZ157oQRoundTripsWithQoZ157 checks that
// ConvertVecLZ157oQ/ConvertVecKZ157oQ (Z157 -> ZQ) are the inverse of
// ConvertVecLQoZ157/ConvertVecKQoZ157 (ZQ -> Z157) on the whole Z157 range:
// every Z157 representative is already < Q/2, so lifting it into ZQ and
// then reducing back down via ConvertSmallToZ157 must reproduce it exactly.
func TestConvertVecLZ157oQRoundTripsWithQoZ157(t *testing.T) {
	var v VecL[fields.Z157]
	for j := range v {
		v[j] = fields.Z157(0).FromUint(uint32(j % TWidth))
	}

	lifted := ConvertVecLZ157oQ(v)
	got := ConvertVecLQoZ157(lifted)
	if got != v {
		t.Fatalf("ConvertVecLQoZ157(ConvertVecLZ157oQ(v)) != v")
	}
}

// TestConvertVecKZ157oQRoundTripsWithQoZ157 mirrors
// TestConvertVecLZ157oQRoundTripsWithQoZ157 for VecK.
func TestConvertVecKZ157oQRoundTripsWithQoZ157(t *testing.T) {
	var v VecK[fields.Z157]
	for j := range v {
		v[j] = fields.Z157(0).FromUint(uint32(j % TWidth))
	}

	lifted := ConvertVecKZ157oQ(v)
	got := ConvertVecKQoZ157(lifted)
	if got != v {
		t.Fatalf("ConvertVecKQoZ157(ConvertVecKZ157oQ(v)) != v")
	}
}

// TestRandLinCombAllZeroIsZero checks that an all-zero bZ/bW always
// accumulates to the zero element, regardless of the coefficients drawn from
// prng - every term is (zero lifted to F2_128) * coefficient, which is zero
// no matter the coefficient.
func TestRandLinCombAllZeroIsZero(t *testing.T) {
	var bZ VecL[fields.F2_8]
	var bW VecK[fields.F2_8]

	got := RandLinComb(rand.Reader, bZ, bW)
	if got != (fields.F2_128{}) {
		t.Fatalf("RandLinComb(all-zero bZ/bW) = %+v, want the zero element", got)
	}
}

// TestRandLinCombSingleOneInBZGivesFirstCoefficient pins down RandLinComb's
// exact behavior, rather than just zero/non-zero: with only bZ[0] set to 1
// and everything else zero, the result must be exactly the first 16 bytes
// RandLinComb reads from prng, decoded as an F2_128 element - since 1 lifts
// to F2_128's multiplicative identity, and every other term is zeroed out by
// its zero bZ/bW entry. The reader only needs to supply those 16 bytes:
// once exhausted, io.ReadFull's error is ignored (by design) and every later
// draw is multiplied by a zero entry anyway.
func TestRandLinCombSingleOneInBZGivesFirstCoefficient(t *testing.T) {
	var bZ VecL[fields.F2_8]
	var bW VecK[fields.F2_8]
	bZ[0] = fields.F2_8(1)

	firstCoeffBytes := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	want := fields.F2_128{}.FromBytes([16]byte(firstCoeffBytes))

	got := RandLinComb(bytes.NewReader(firstCoeffBytes), bZ, bW)
	if got != want {
		t.Fatalf("RandLinComb with only bZ[0]=1 = %+v, want the first coefficient read as-is: %+v", got, want)
	}
}

// TestRandLinCombNonZeroPatternsGiveNonZeroResult checks a handful of
// non-all-zero bZ/bW patterns against real randomness: the odds of a
// non-trivial linear combination happening to cancel to exactly zero are
// 2^-128, so a non-zero result is what every one of these should produce.
func TestRandLinCombNonZeroPatternsGiveNonZeroResult(t *testing.T) {
	tests := []struct {
		name string
		bZ   VecL[fields.F2_8]
		bW   VecK[fields.F2_8]
	}{
		{
			name: "single 1 in bZ",
			bZ:   VecL[fields.F2_8]{0: 1},
		},
		{
			name: "single 1 in bW",
			bW:   VecK[fields.F2_8]{0: 1},
		},
		{
			name: "single 1 at the end of bZ",
			bZ:   VecL[fields.F2_8]{L*N - 1: 1},
		},
		{
			name: "single 1 at the end of bW",
			bW:   VecK[fields.F2_8]{K*N - 1: 1},
		},
		{
			name: "a non-unit F2_8 value",
			bZ:   VecL[fields.F2_8]{0: 0x53},
		},
		{
			name: "scattered 1s across both bZ and bW",
			bZ:   VecL[fields.F2_8]{0: 1, L*N/2 + 1: 1},
			bW:   VecK[fields.F2_8]{K*N/2 - 1: 1, K*N - 1: 1},
		},
		{
			name: "all-ones bZ and bW",
			bZ:   allOnesVecL(),
			bW:   allOnesVecK(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RandLinComb(rand.Reader, tc.bZ, tc.bW)
			if got == (fields.F2_128{}) {
				t.Fatalf("RandLinComb(%s) = 0, want a non-zero element", tc.name)
			}
		})
	}
}

func allOnesVecL() VecL[fields.F2_8] {
	var v VecL[fields.F2_8]
	for j := range v {
		v[j] = 1
	}
	return v
}

func allOnesVecK() VecK[fields.F2_8] {
	var v VecK[fields.F2_8]
	for j := range v {
		v[j] = 1
	}
	return v
}

// TestW1BaseIs44 pins down w1Base's derived value against the literal 44
// the "44" in CompressVecK44/DecompressVecK44/VecKCompressed's names (and in
// w_1's own range) refers to - if ML-DSA-44's Gamma2/Alpha parameters ever
// changed, this is the test that would catch w1Base silently becoming
// something else.
func TestW1BaseIs44(t *testing.T) {
	if w1Base != 44 {
		t.Fatalf("w1Base = %d, want 44", w1Base)
	}
}

// TestW1ArityIsTheMostThatFitsUnderQ checks the claim CompressVecK44's doc
// comment makes: w1Arity is the largest number of w1Base-ary digits that
// packs into one fields.ZQ element without wrapping around mod Q - i.e.
// w1Base^w1Arity < Q, but one more digit wouldn't fit
// (w1Base^(w1Arity+1) >= Q).
func TestW1ArityIsTheMostThatFitsUnderQ(t *testing.T) {
	fits := uint64(1)
	for range w1Arity {
		fits *= uint64(w1Base)
	}
	if fits >= uint64(fields.Q) {
		t.Fatalf("w1Base^w1Arity = %d, want < Q = %d", fits, fields.Q)
	}

	oneMore := fits * uint64(w1Base)
	if oneMore < uint64(fields.Q) {
		t.Fatalf("w1Base^(w1Arity+1) = %d, want >= Q = %d - w1Arity could pack one more digit", oneMore, fields.Q)
	}
}

// TestCompressVecK44EncodingMatchesFormula pins down CompressVecK44's exact
// positional encoding on a hand-picked first quad, independently of
// DecompressVecK44 - i.e. this would catch CompressVecK44 and
// DecompressVecK44 sharing the same bug and still round-tripping.
func TestCompressVecK44EncodingMatchesFormula(t *testing.T) {
	var v VecK[fields.ZQ]
	v[0] = fields.ZQ(0).FromUint(1)
	v[1] = fields.ZQ(0).FromUint(2)
	v[2] = fields.ZQ(0).FromUint(3)
	v[3] = fields.ZQ(0).FromUint(4)

	got := CompressVecK44(v)
	want := uint32(1) + 44*2 + 44*44*3 + 44*44*44*4
	if uint32(got[0]) != want {
		t.Fatalf("CompressVecK44(v)[0] = %d, want %d", uint32(got[0]), want)
	}
}

// TestCompressUnpackVecK44RoundTrip checks that
// DecompressVecK44(CompressVecK44(v)) == v whenever every coordinate of v
// is < w1Base, as w_1 itself always is.
func TestCompressUnpackVecK44RoundTrip(t *testing.T) {
	var v VecK[fields.ZQ]
	for j := range v {
		v[j] = fields.ZQ(0).FromUint(uint32(j) % w1Base)
	}

	compressed := CompressVecK44(v)
	got := DecompressVecK44(compressed)
	if got != v {
		t.Fatalf("DecompressVecK44(CompressVecK44(v)) != v")
	}
}

// TestCompressUnpackVecK44RoundTripZeroAndMax checks the extremes of
// w_1's range specifically - every coordinate 0, and every coordinate
// w1Base-1 - rather than only the spread TestCompressUnpackVecK44RoundTrip
// uses.
func TestCompressUnpackVecK44RoundTripZeroAndMax(t *testing.T) {
	var zero, max VecK[fields.ZQ]
	for j := range max {
		max[j] = fields.ZQ(0).FromUint(w1Base - 1)
	}

	if got := DecompressVecK44(CompressVecK44(zero)); got != zero {
		t.Fatalf("DecompressVecK44(CompressVecK44(all-zero)) != all-zero")
	}
	if got := DecompressVecK44(CompressVecK44(max)); got != max {
		t.Fatalf("DecompressVecK44(CompressVecK44(all-(w1Base-1))) != all-(w1Base-1)")
	}
}

// TestCompressVecK44IsLinearOverShares checks the property CompressVecK44's
// doc comment claims, and that any caller compressing w_1 before opening it
// relies on: compressing each party's own Shamir share of v, then
// reconstructing the compressed shares via ReconstructVecKCompressed, gives
// exactly the same VecKCompressed as reconstructing v first (via
// ReconstructVecK) and compressing the result directly - i.e.
// CompressVecK44 commutes with Shamir sharing, so compression can happen
// before reconstruction instead of after.
func TestCompressVecK44IsLinearOverShares(t *testing.T) {
	const threshold, numShares = 2, 5

	var v VecK[fields.ZQ]
	for j := range v {
		v[j] = fields.ZQ(0).FromUint(uint32(j*7+3) % w1Base)
	}

	shares := ShareVecK(v, threshold, numShares)
	compressedShares := make([]VecKCompressed, numShares)
	for i, s := range shares {
		compressedShares[i] = CompressVecK44(s)
	}

	gotCompressed, err := ReconstructVecKCompressed(compressedShares, threshold, numShares)
	if err != nil {
		t.Fatalf("ReconstructVecKCompressed failed: %v", err)
	}

	want := CompressVecK44(v)
	if gotCompressed != want {
		t.Fatalf("reconstructing per-party compressed shares != compressing the reconstructed v directly")
	}
	if got := DecompressVecK44(gotCompressed); got != v {
		t.Fatalf("DecompressVecK44(reconstructed compressed shares) != v")
	}
}
