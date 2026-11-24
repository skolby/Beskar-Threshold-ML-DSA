package mldsa44

import (
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	"t-mldsa/src/circl-mldsa/internal/sha3"
	common "t-mldsa/src/circl-mldsa/sign/internal/dilithium"
)

func DealerGenerateKeys() (*PublicKey, VecL, VecK, error) {
	pk, sk, err := GenerateKey(cryptoRand.Reader)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return nil, VecL{}, VecK{}, err
	}
	return pk, sk.s1, sk.s2, nil
}

/*
	Extracted functionality from SignTo to expose partial signatures to the dealer protocol.
*/
//
//nolint:funlen
func DealerPreSign(pk *PublicKey) (VecK, VecK, VecL) {
	var rhop [64]byte
	var eSeed [64]byte
	var y, yh VecL
	var w, w0, w1, ew VecK
	var yNonce uint16

	cryptoRand.Read(rhop[:])
	// Sample y given randomness
	VecLDeriveUniformLeGamma1(&y, &rhop, yNonce)
	yNonce += uint16(L)

	// Set w to A y
	yh = y
	yh.NTT()
	for i := 0; i < K; i++ {
		PolyDotHat(&w[i], &pk.A[i], &yh)
		w[i].ReduceLe2Q()
		w[i].InvNTT()
	}

	// Blind w with fresh η-bounded noise, drawn from the same distribution
	// used to sample sk.s1/s2 (PolyDeriveUniformLeqEta), before decomposing
	// it into w₀ and w₁.
	cryptoRand.Read(eSeed[:])
	for i := uint16(0); i < K; i++ {
		PolyDeriveUniformLeqEta(&ew[i], &eSeed, i)
	}
	w.Add(&w, &ew)

	// Decompose w into w₀ and w₁
	w.NormalizeAssumingLe2Q()
	w.Decompose(&w0, &w1)

	// Decompose's a0+q construction can leave w0 (and, via the a₁=0 corner
	// case, w1) slightly above the canonical <q range; normalize so callers
	// can treat every returned coefficient as a proper mod-q representative.
	w0.Normalize()
	w1.Normalize()
	y.Normalize()
	return w0, w1, y
}

// ComputeChallenge returns c~ and the challenge polynomial c itself, both in
// the standard (non-NTT) domain - callers that need it in NTT form (e.g.
// computeResponse's ch parameter) must call .NTT() themselves.
func ComputeChallenge(pk *PublicKey, w1 VecK, msg func(io.Writer)) ([CTildeSize]byte, common.Poly) {
	var mu [64]byte
	var c [CTildeSize]byte
	var chal common.Poly
	var w1Packed [PolyW1Size * K]byte

	//  μ = CRH(tr ‖ msg)
	h := sha3.NewShake256()
	_, _ = h.Write(pk.tr[:])
	msg(&h)
	_, _ = h.Read(mu[:])

	h.Reset()
	// c~ = H(μ ‖ w₁)
	w1.PackW1(w1Packed[:])
	h.Reset()
	_, _ = h.Write(mu[:])
	_, _ = h.Write(w1Packed[:])
	_, _ = h.Read(c[:])

	PolyDeriveUniformBall(&chal, c[:])
	return c, chal
}

// MulConstVecL scales each of the L polynomials in v by the constant
// polynomial c, multiplying in the polynomial ring via the NTT (NTT,
// pointwise multiply, InvNTT). c and v are both taken and returned in the
// standard (non-NTT) domain; neither is modified.
//
// This lets a party locally scale its own additive secret share of a VecL
// by a public constant (e.g. the challenge) without interaction: since
// v = Σ shares, c·v = Σ c·share, so each party can just multiply its own
// share by c.
func MulConstVecL(c common.Poly, v VecL) VecL {
	ch := c
	ch.NTT()

	var result VecL
	for i := 0; i < L; i++ {
		vh := v[i]
		vh.NTT()
		result[i].MulHat(&ch, &vh)
		result[i].InvNTT()
	}
	result.NormalizeAssumingLe2Q()
	return result
}

// MulConstVecK mirrors MulConstVecL for VecK.
func MulConstVecK(c common.Poly, v VecK) VecK {
	ch := c
	ch.NTT()

	var result VecK
	for i := 0; i < K; i++ {
		vh := v[i]
		vh.NTT()
		result[i].MulHat(&ch, &vh)
		result[i].InvNTT()
	}
	result.NormalizeAssumingLe2Q()
	return result
}

func FinalizeSignature(pk *PublicKey, c [CTildeSize]byte, z VecL) ([]byte, error) {
	var ch common.Poly
	var sig unpackedSignature
	var t0, t1, t0h, ct0, ct, th, Az, Azmct, r0, r1, r0pct0 VecK
	var zh VecL

	pk.t.Power2Round(&t0, &t1)
	t0h = t0
	t0h.NTT()

	sig.c = c
	sig.z = z
	PolyDeriveUniformBall(&ch, c[:])
	ch.NTT()

	// Compute c·t₀ and c·t
	th = pk.t
	th.NTT()
	for i := 0; i < K; i++ {
		ct0[i].MulHat(&ch, &t0h[i])
		ct0[i].InvNTT()
		ct[i].MulHat(&ch, &th[i])
		ct[i].InvNTT()
	}
	ct0.NormalizeAssumingLe2Q()
	ct.NormalizeAssumingLe2Q()

	// Ensure ‖c·t₀‖_∞ < γ₂.
	if ct0.Exceeds(Gamma2) {
		return nil, fmt.Errorf("c·t₀ exceeds γ₂")
	}

	// MPC-friendly hint computation without using w as input:
	// r = Az - c·t and q = r + c·t₀. Build hint as MakeHint(r₀+c·t₀, r₁).
	zh = z
	zh.NTT()
	for i := 0; i < K; i++ {
		PolyDotHat(&Az[i], &pk.A[i], &zh)
		Az[i].ReduceLe2Q()
		Az[i].InvNTT()
	}
	Azmct.Sub(&Az, &ct)
	Azmct.Normalize()
	Azmct.Decompose(&r0, &r1)
	r0.NormalizeAssumingLe2Q()

	r0pct0.Add(&r0, &ct0)
	r0pct0.NormalizeAssumingLe2Q()

	hintPop := sig.hint.MakeHint(&r0pct0, &r1)
	if hintPop > Omega {
		return nil, fmt.Errorf("hint population exceeds Ω")
	}

	signature := make([]byte, SignatureSize)
	sig.Pack(signature[:])
	return signature, nil
}
