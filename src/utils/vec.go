package utils

import (
	"crypto/subtle"
	"io"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	"t-mldsa/src/fields"
	ss "t-mldsa/src/secretsharing"
)

// N, K, L and TWidth mirror the ML-DSA-44 parameters of the same name in
// package protocol (N/K/L/t there) - duplicated here, rather than imported,
// so that VecL/VecK/LutL/LutK can live in utils without utils importing
// protocol (which would cycle back, since protocol needs utils for
// marshalling/encryption). protocol re-exposes these as its own N/K/L/t
// constants, aliased to the values here, so the two stay in lockstep.
const (
	N      = 256
	K      = 4
	L      = 4
	TWidth = 157
)

type VecL[T fields.FieldElement[T]] [(L * N)]T
type VecK[T fields.FieldElement[T]] [(K * N)]T

type LutL[T fields.FieldElement[T]] [(L * N)][TWidth]T
type LutK[T fields.FieldElement[T]] [(K * N)][TWidth]T

// Coefficient wise threshold-Shamir sharing of VecL, resulting in a slice of vectors os shares, each VecL contains the shares for one party.
func ShareVecL[T fields.FieldElement[T]](secrets VecL[T], threshold, numShares int) []VecL[T] {
	var shares []VecL[T]

	shares = make([]VecL[T], numShares)
	for i := 0; i < numShares; i++ {
		shares[i] = VecL[T]{}
	}

	// Share each element of the vector
	for j := range L * N {
		sharej := ss.Share(secrets[j], threshold, numShares)
		for i := range numShares {
			shares[i][j] = sharej[i]
		}
	}
	return shares
}

// Coefficient wise threshold-Shamir sharing of VecK, resulting in a slice of vectors os shares, each VecK contains the shares for one party.
func ShareVecK[T fields.FieldElement[T]](secrets VecK[T], threshold, numShares int) []VecK[T] {
	var shares []VecK[T]

	shares = make([]VecK[T], numShares)
	for i := 0; i < numShares; i++ {
		shares[i] = VecK[T]{}
	}

	// Share each element of the vector
	for j := range K * N {
		sharej := ss.Share(secrets[j], threshold, numShares)
		for i := range numShares {
			shares[i][j] = sharej[i]
		}
	}
	return shares
}

// AddVecL adds two VecL[T] coordinate-wise, using the field's own Add.
func AddVecL[T fields.FieldElement[T]](a, b VecL[T]) VecL[T] {
	var sum VecL[T]
	for j := range L * N {
		sum[j] = a[j].Add(b[j])
	}
	return sum
}

// AddVecK adds two VecK[T] coordinate-wise, using the field's own Add.
func AddVecK[T fields.FieldElement[T]](a, b VecK[T]) VecK[T] {
	var sum VecK[T]
	for j := range K * N {
		sum[j] = a[j].Add(b[j])
	}
	return sum
}

// AddConstVecL adds the same constant c to every coordinate of v, using the
// field's own Add.
func AddConstVecL[T fields.FieldElement[T]](v VecL[T], c T) VecL[T] {
	var out VecL[T]
	for j := range L * N {
		out[j] = v[j].Add(c)
	}
	return out
}

// AddConstVecK mirrors AddConstVecL for VecK.
func AddConstVecK[T fields.FieldElement[T]](v VecK[T], c T) VecK[T] {
	var out VecK[T]
	for j := range K * N {
		out[j] = v[j].Add(c)
	}
	return out
}

// NegVecK negates a VecK[T] coordinate-wise, using the field's own Sub from
// its own Zero.
func NegVecK[T fields.FieldElement[T]](v VecK[T]) VecK[T] {
	var out VecK[T]
	for j := range K * N {
		out[j] = out[j].Zero().Sub(v[j])
	}
	return out
}

// ShareLutL shares each entry of a lookup table indexed by an L*N-sized
// vector.
func ShareLutL[T fields.FieldElement[T]](secrets LutL[T], threshold, numShares int) []LutL[T] {
	shares := make([]LutL[T], numShares)

	for j := range L * N {
		for k := range TWidth {
			sharejk := ss.Share(secrets[j][k], threshold, numShares)
			for i := range numShares {
				shares[i][j][k] = sharejk[i]
			}
		}
	}
	return shares
}

// ShareLutK shares each entry of a lookup table indexed by a K*N-sized
// vector.
func ShareLutK[T fields.FieldElement[T]](secrets LutK[T], threshold, numShares int) []LutK[T] {
	shares := make([]LutK[T], numShares)

	for j := range K * N {
		for k := range TWidth {
			sharejk := ss.Share(secrets[j][k], threshold, numShares)
			for i := range numShares {
				shares[i][j][k] = sharejk[i]
			}
		}
	}
	return shares
}

// ReconstructVecL reconstructs a VecL[T] from one vector of shares per party
func ReconstructVecL[T fields.FieldElement[T]](shares []VecL[T], threshold, numShares int) (VecL[T], error) {
	var out VecL[T]
	r := ss.NewReconstructor[T](threshold, numShares)
	col := make([]T, numShares)
	for j := range L * N {
		for i := range numShares {
			col[i] = shares[i][j]
		}
		v, err := r.Reconstruct(col)
		if err != nil {
			return out, err
		}
		out[j] = v
	}
	return out, nil
}

// ReconstructVecK reconstructs a VecK[T] from one vector of shares per party
func ReconstructVecK[T fields.FieldElement[T]](shares []VecK[T], threshold, numShares int) (VecK[T], error) {
	var out VecK[T]
	r := ss.NewReconstructor[T](threshold, numShares)
	col := make([]T, numShares)
	for j := range K * N {
		for i := range numShares {
			col[i] = shares[i][j]
		}
		v, err := r.Reconstruct(col)
		if err != nil {
			return out, err
		}
		out[j] = v
	}
	return out, nil
}

// RandVecL samples a fresh, uniformly random vector of L*N field elements,
// using the field's own sampler.
func RandVecL[T fields.FieldElement[T]]() (VecL[T], error) {
	var v VecL[T]
	for j := range L * N {
		var err error
		v[j], err = v[j].Rand()
		if err != nil {
			return v, err
		}
	}
	return v, nil
}

// RandVecK samples a fresh, uniformly random vector of K*N field elements,
// using the field's own sampler.
func RandVecK[T fields.FieldElement[T]]() (VecK[T], error) {
	var v VecK[T]
	for j := range K * N {
		var err error
		v[j], err = v[j].Rand()
		if err != nil {
			return v, err
		}
	}
	return v, nil
}

// ToFieldElementL converts an mldsa44.VecL into a VecL[fields.ZQ].
func ToFieldElementL(v mldsa44.VecL) VecL[fields.ZQ] {
	var v_ VecL[fields.ZQ]
	for j := range L {
		for u := range N {
			v_[j*N+u] = fields.ZQ(0).FromUint(v[j][u])
		}
	}
	return v_
}

// ToFieldElementK converts an mldsa44.VecK into a VecK[fields.ZQ].
func ToFieldElementK(v mldsa44.VecK) VecK[fields.ZQ] {
	var v_ VecK[fields.ZQ]
	for j := range K {
		for u := range N {
			v_[j*N+u] = fields.ZQ(0).FromUint(v[j][u])
		}
	}
	return v_
}

// FromFieldElementL converts a VecL[fields.ZQ] back into
// mldsa44.VecL representation for compatibility with mldsa44 functions
func FromFieldElementL(v VecL[fields.ZQ]) mldsa44.VecL {
	var v_ mldsa44.VecL
	for j := range L {
		for u := range N {
			v_[j][u] = uint32(v[j*N+u])
		}
	}
	return v_
}

// FromFieldElementK converts a VecK[fields.ZQ] back into
// mldsa44.VecK representation for compatibility with mldsa44 functions
func FromFieldElementK(v VecK[fields.ZQ]) mldsa44.VecK {
	var v_ mldsa44.VecK
	for j := range K {
		for u := range N {
			v_[j][u] = uint32(v[j*N+u])
		}
	}
	return v_
}

// MulConstVecL multiplies a VecL[fields.ZQ] share vector by the constant
// polynomial c, using the polynomial ring's NTT (mldsa44.MulConstVecL).
// Only supported over fields.ZQ, since the NTT is only defined for that
// modulus. c is the coefficient array of a single polynomial in the
// standard (non-NTT) domain, shared by every one of the L blocks in v - e.g.
// the challenge polynomial returned by mldsa44.ComputeChallenge.
//
// Multiplication by a public constant distributes over addition, so a party
// can apply this straight to its own additive share of a secret to get its
// share of c times that secret, without interaction.
func MulConstVecL(c [N]uint32, v VecL[fields.ZQ]) VecL[fields.ZQ] {
	return ToFieldElementL(mldsa44.MulConstVecL(c, FromFieldElementL(v)))
}

// MulConstVecK mirrors MulConstVecL for VecK.
func MulConstVecK(c [N]uint32, v VecK[fields.ZQ]) VecK[fields.ZQ] {
	return ToFieldElementK(mldsa44.MulConstVecK(c, FromFieldElementK(v)))
}

// CanonicalizeChallenge maps each ternary coefficient of a challenge
// polynomial c (0, 1 or Q-1) to what ConvertSmallToZ157 followed by
// ConvertZ157ToZQ would produce: 0 and 1 pass through unchanged, and Q-1
// (i.e. -1) becomes 156, its canonical Z157 representative lifted into ZQ.
func CanonicalizeChallenge(c [N]uint32) [N]uint32 {
	var out [N]uint32
	for i := range N {
		// isMinusOne is 1 iff c[i] == Q-1: the only coefficient value >= 2.
		isMinusOne := uint32(subtle.ConstantTimeLessOrEq(2, int(c[i])))
		out[i] = isMinusOne*(uint32(fields.P)-1) + (1-isMinusOne)*c[i]
	}
	return out
}

// ConvertVecLQoZ157 reduces every coordinate of a VecL[fields.ZQ] down to
// its Z157 residue.
func ConvertVecLQoZ157(v VecL[fields.ZQ]) VecL[fields.Z157] {
	var v_ VecL[fields.Z157]
	for j := range L * N {
		v_[j] = fields.ConvertSmallToZ157(v[j])
	}
	return v_
}

// ConvertVecKQoZ157 mirrors ConvertVecLQoZ157 for VecK.
func ConvertVecKQoZ157(v VecK[fields.ZQ]) VecK[fields.Z157] {
	var v_ VecK[fields.Z157]
	for j := range K * N {
		v_[j] = fields.ConvertSmallToZ157(v[j])
	}
	return v_
}

// RandLinComb draws one fresh random F2_128 coefficient per entry of bZ and
// bW from prng, lifts each F2_8 entry into F2_128 via ToF2_128, and
// accumulates the sum of every entry times its coefficient - a random
// linear combination of this party's LUT-lookup shares, batching the L*N +
// K*N range-check openings into a single F2_128 check.
//
// prng is assumed to be an effectively infinite, non-failing stream (e.g.
// the SHAKE128 XOF built in Round3) - io.ReadFull's error is ignored, so a
// prng that runs out or errors will silently feed zero bytes into the
// affected coefficient(s) rather than surfacing a failure.
func RandLinComb(prng io.Reader, bZ VecL[fields.F2_8], bW VecK[fields.F2_8]) fields.F2_128 {
	var acc fields.F2_128
	var buf [16]byte

	for j := range L * N {
		_, _ = io.ReadFull(prng, buf[:])
		coeff := fields.F2_128{}.FromBytes(buf)
		acc = acc.Add(bZ[j].ToF2_128().Mult(coeff))
	}

	for j := range K * N {
		_, _ = io.ReadFull(prng, buf[:])
		coeff := fields.F2_128{}.FromBytes(buf)
		acc = acc.Add(bW[j].ToF2_128().Mult(coeff))
	}

	return acc
}

// ConvertVecLZ157oQ lifts every coordinate of a VecL[fields.Z157] into
// fields.ZQ.
func ConvertVecLZ157oQ(v VecL[fields.Z157]) VecL[fields.ZQ] {
	var v_ VecL[fields.ZQ]
	for j := range L * N {
		v_[j] = fields.ConvertZ157ToZQ(v[j])
	}
	return v_
}

// ConvertVecKZ157oQ mirrors ConvertVecLZ157oQ for VecK.
func ConvertVecKZ157oQ(v VecK[fields.Z157]) VecK[fields.ZQ] {
	var v_ VecK[fields.ZQ]
	for j := range K * N {
		v_[j] = fields.ConvertZ157ToZQ(v[j])
	}
	return v_
}

// w1Base is the base CompressVecK44/DecompressVecK44 use to pack ML-DSA-44
// w_1 values, each known to lie in [0, w1Base), into fields.ZQ elements:
// w1Base = (Q-1)/Alpha, the number of distinct values ML-DSA-44's own
// decompose() can produce for a coefficient's high bits (see
// mldsa44/rounding.go's decompose doc comment - Alpha = 2*Gamma2 there is
// the α it refers to).
const w1Base = (fields.Q - 1) / mldsa44.Alpha

// w1Arity is the number of w1Base-ary digits CompressVecK44/
// DecompressVecK44 pack into (resp. unpack from) a single fields.ZQ
// element. w1Base^w1Arity must stay below Q so a packed value never wraps
// around mod Q: w1Base^4 = 3,748,096 < Q = 8,380,417 < w1Base^5 =
// 164,916,224, so 4 is the most digits this can pack losslessly.
const w1Arity = 4

// VecKCompressed is the result of compressing a VecK[fields.ZQ] w1Arity(=4)-to-1
// via CompressVecK44 - see its doc comment. K*N must be a multiple of
// w1Arity for this to cover every coordinate (true for K=4, N=256).
type VecKCompressed [(K * N) / w1Arity]fields.ZQ

// CompressVecK44 packs a VecK[fields.ZQ] into a VecKCompressed, a vector w1Arity
// (4) times shorter: each consecutive group of w1Arity coordinates
// v[4i], v[4i+1], v[4i+2], v[4i+3] - every one of which must be < w1Base,
// e.g. w_1's own range (see w1Base's doc comment) - is packed into one
// output coordinate, positionally:
//
//	v[4i] + w1Base*v[4i+1] + w1Base²*v[4i+2] + w1Base³*v[4i+3]
//
// DecompressVecK44 is the inverse. A coordinate that isn't < w1Base still
// packs without error, it just won't round-trip.
//
// This is computed entirely with fields.ZQ's own Add/Mult, i.e. it's a
// ZQ-linear combination of v's coordinates - so it's just as valid applied
// to each party's own Shamir share of v as it is applied to v itself:
// Shamir sharing is linear, so compressing every party's shares the same
// way produces exactly the shares of the compressed vector. The compressed
// vector can then be reconstructed (Lagrange-interpolated) directly,
// without ever reconstructing the 4x larger uncompressed v first.
func CompressVecK44(v VecK[fields.ZQ]) VecKCompressed {
	var out VecKCompressed
	base := fields.ZQ(0).FromUint(w1Base)
	for i := range out {
		p := v[w1Arity*i]
		weight := base
		for j := 1; j < w1Arity; j++ {
			p = p.Add(v[w1Arity*i+j].Mult(weight))
			weight = weight.Mult(base)
		}
		out[i] = p
	}
	return out
}

// DecompressVecK44 is the inverse of CompressVecK44: it decodes each packed
// coordinate back into w1Arity values via base-w1Base long division.
// Assumes every packed coordinate is < w1Base^w1Arity - true of any output
// of CompressVecK44 given inputs that were each < w1Base, and true of any
// Lagrange reconstruction of Shamir shares CompressVecK44 was applied to
// (the reconstructed secret is exactly the packed value, unless the shares
// were tampered with).
//
// Not constant-time: it uses Go's own '/' and '%' on values derived from
// compressed, whose timing can depend on those values. Fine here since
// w_1 isn't sensitive, but this isn't safe to reuse for a compressed
// secret that is.
func DecompressVecK44(compressed VecKCompressed) VecK[fields.ZQ] {
	var out VecK[fields.ZQ]
	for i, p := range compressed {
		x := uint32(p)
		for j := range w1Arity {
			out[w1Arity*i+j] = fields.ZQ(0).FromUint(x % w1Base)
			x /= w1Base
		}
	}
	return out
}

// ReconstructVecKCompressed reconstructs a VecKCompressed from one share
// per party, one Lagrange interpolation per coordinate - mirrors
// ReconstructVecK, but over VecKCompressed's fixed (K*N)/w1Arity fields.ZQ
// coordinates rather than ReconstructVecK's generic VecK[T]: VecKCompressed
// isn't itself generic over T (CompressVecK44/DecompressVecK44 only make
// sense for fields.ZQ), so it can't reuse ReconstructVecK directly.
func ReconstructVecKCompressed(shares []VecKCompressed, threshold, numShares int) (VecKCompressed, error) {
	var out VecKCompressed
	r := ss.NewReconstructor[fields.ZQ](threshold, numShares)
	col := make([]fields.ZQ, numShares)
	for j := range out {
		for i := range numShares {
			col[i] = shares[i][j]
		}
		v, err := r.Reconstruct(col)
		if err != nil {
			return out, err
		}
		out[j] = v
	}
	return out, nil
}
