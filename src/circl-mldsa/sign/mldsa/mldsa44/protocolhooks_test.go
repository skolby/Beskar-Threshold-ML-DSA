package mldsa44

import (
	cryptoRand "crypto/rand"
	"fmt"
	"io"
	common "t-mldsa/src/circl-mldsa/sign/internal/dilithium"
	"testing"
)

func TestProtocolHooks(t *testing.T) {
	ctx := []byte("Test context")
	msg := []byte("Signing with ML-DSA-44")
	msgWriter := func(w io.Writer) {
		_, _ = w.Write([]byte{0})
		_, _ = w.Write([]byte{byte(len(ctx))})

		if ctx != nil {
			_, _ = w.Write(ctx)
		}
		w.Write(msg)
	}

	pk, sk, err := GenerateKey(cryptoRand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	var completedVerifyingSignatures int
	var rejectedSignatures int
	var failedFinalizeSignatures int

	for i := range 1000 {
		w0, w1, y := DealerPreSign(pk)
		c, chal := ComputeChallenge(pk, w1, msgWriter)
		chal.NTT() // computeResponse expects its ch argument in NTT form
		rejected, z := computeResponse(sk, chal, w0, y)
		if rejected {
			rejectedSignatures++
			continue
		}

		// Manual bounds checks for z, w
		sig, err := FinalizeSignature(pk, c, z)

		if err == nil {

			// fmt.Printf("Expected w1.     : %v\n", w1)
			if !Verify(pk, msgWriter, sig) {
				t.Errorf("Signature %d Verify failed", i)
			} else {
				completedVerifyingSignatures++
			}
			continue
		} else {
			failedFinalizeSignatures++
		}
	}
	fmt.Printf("Completed verifying signatures: %d\n", completedVerifyingSignatures)
	fmt.Printf("Rejected signatures: %d\n", rejectedSignatures)
	fmt.Printf("Failed FinalizeSignature: %d\n", failedFinalizeSignatures)
}

func computeResponse(sk *PrivateKey, ch common.Poly, w0 VecK, y VecL) (bool, VecL) {
	var w0mcs2 VecK
	var z VecL
	// Ensure ‖ w₀ - c·s2 ‖_∞ < γ₂ - β.
	//
	// By Lemma 3 of the specification this is equivalent to checking that
	// both ‖ r₀ ‖_∞ < γ₂ - β and r₁ = w₁, for the decomposition
	// w - c·s₂	 = r₁ α + r₀ as computed by decompose().
	// See also §4.1 of the specification.
	for i := 0; i < K; i++ {
		w0mcs2[i].MulHat(&ch, &sk.s2h[i])
		w0mcs2[i].InvNTT()
	}
	w0mcs2.Sub(&w0, &w0mcs2)
	w0mcs2.Normalize()

	if w0mcs2.Exceeds(Gamma2 - Beta) {
		return true, VecL{}
	}

	// z = y + c·s₁
	for i := 0; i < L; i++ {
		z[i].MulHat(&ch, &sk.s1h[i])
		z[i].InvNTT()
	}
	z.Add(&z, &y)
	z.Normalize()

	// Ensure  ‖z‖_∞ < γ₁ - β
	if z.Exceeds(Gamma1 - Beta) {
		return true, VecL{}
	}
	return false, z
}
