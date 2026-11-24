package mldsa44

import (
	"io"
	"t-mldsa/src/circl-mldsa/internal/sha3"
)

/*
	Extracted functionality from mldsa44/dilithium.go to expose partial signatures to the dealer protocol. This is necessary because the dealer needs to generate shares of the commitment, which requires access to the internal signing process of ML-DSA-44.
*/
//
//nolint:funlen
func PreSignInternal(sk *PrivateKey, msg, ctx []byte, rnd [32]byte) (VecK, VecK, VecL) {

	writer := func(w io.Writer) {
		_, _ = w.Write([]byte{0})
		_, _ = w.Write([]byte{byte(len(ctx))})

		if ctx != nil {
			_, _ = w.Write(ctx)
		}
		w.Write(msg)
	}
	var mu, rhop [64]byte
	var y, yh VecL
	var w, w0, w1 VecK
	// w0mcs2, ct0, w0mcs2pct0 VecK
	// var ch common.Poly
	var yNonce uint16

	//  μ = CRH(tr ‖ msg)
	h := sha3.NewShake256()
	_, _ = h.Write(sk.tr[:])
	writer(&h)
	_, _ = h.Read(mu[:])

	// ρ' = CRH(key ‖ μ)
	h.Reset()
	_, _ = h.Write(sk.key[:])
	if NIST {
		_, _ = h.Write(rnd[:])
	}
	_, _ = h.Write(mu[:])
	_, _ = h.Read(rhop[:])

	// Main rejection loop

	// y = ExpandMask(ρ', key)
	VecLDeriveUniformLeGamma1(&y, &rhop, yNonce)
	yNonce += uint16(L)

	// Set w to A y
	yh = y
	yh.NTT()
	for i := 0; i < K; i++ {
		PolyDotHat(&w[i], &sk.A[i], &yh)
		w[i].ReduceLe2Q()
		w[i].InvNTT()
	}

	// Decompose w into w₀ and w₁
	w.NormalizeAssumingLe2Q()
	w.Decompose(&w0, &w1)

	return w0, w1, y
}
