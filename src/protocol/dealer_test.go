package protocol

import (
	"testing"

	"t-mldsa/src/fields"
	ss "t-mldsa/src/secretsharing"
	"t-mldsa/src/utils"
)

// --- helpers: reconstruct a value that DealPreSig spread across per-party
// PreprocessingStates, one Lagrange interpolation per coordinate/entry.
// (utils.ReconstructVecL/utils.ReconstructVecK live in utils/vec.go: Round2 needs them too.) ---

func reconstructLutL[T fields.FieldElement[T]](shares []LutL[T], threshold, numShares int) (LutL[T], error) {
	var out LutL[T]
	r := ss.NewReconstructor[T](threshold, numShares)
	col := make([]T, numShares)
	for j := range L * N {
		for k := range t {
			for i := range numShares {
				col[i] = shares[i][j][k]
			}
			v, err := r.Reconstruct(col)
			if err != nil {
				return out, err
			}
			out[j][k] = v
		}
	}
	return out, nil
}

func reconstructLutK[T fields.FieldElement[T]](shares []LutK[T], threshold, numShares int) (LutK[T], error) {
	var out LutK[T]
	r := ss.NewReconstructor[T](threshold, numShares)
	col := make([]T, numShares)
	for j := range K * N {
		for k := range t {
			for i := range numShares {
				col[i] = shares[i][j][k]
			}
			v, err := r.Reconstruct(col)
			if err != nil {
				return out, err
			}
			out[j][k] = v
		}
	}
	return out, nil
}

// TestDealKeys deals key shares for a set of parties and checks:
//  1. every field DealKeys distributes is a valid (threshold, numShares)
//     Shamir sharing (Reconstruct's built-in cross-share consistency check);
//  2. [[s_1]]_t reconstructs to the same secret as [[s_1]]_q, once the
//     latter is reduced mod 157 - i.e. both are shares of the same s1,
//     just under two different moduli.
func TestDealKeys(t *testing.T) {
	const threshold, numShares = 2, 5

	pk, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	if pk == nil {
		t.Fatalf("expected a non-nil public key")
	}
	if len(keys) != numShares {
		t.Fatalf("expected %d key states, got %d", numShares, len(keys))
	}
	for i, k := range keys {
		if k.partyID != i+1 {
			t.Fatalf("keys[%d].partyID = %d, want %d (party indices start at 1)", i, k.partyID, i+1)
		}
	}

	s1QShares := make([]VecL[fields.ZQ], numShares)
	s1TShares := make([]VecL[fields.Z157], numShares)
	s2TShares := make([]VecK[fields.Z157], numShares)
	for i, k := range keys {
		s1QShares[i] = k.s1Q
		s1TShares[i] = k.s1T
		s2TShares[i] = k.s2T
	}

	s1Q, err := utils.ReconstructVecL(s1QShares, threshold, numShares)
	if err != nil {
		t.Fatalf("reconstructing [[s_1]]_q shares: %v", err)
	}
	s1T, err := utils.ReconstructVecL(s1TShares, threshold, numShares)
	if err != nil {
		t.Fatalf("reconstructing [[s_1]]_t shares: %v", err)
	}
	if _, err := utils.ReconstructVecK(s2TShares, threshold, numShares); err != nil {
		t.Fatalf("reconstructing [[s_2]]_t shares: %v", err)
	}

	t.Run("s1T shares reconstruct to s1Q reduced mod 157", func(t *testing.T) {
		want := utils.ConvertVecLQoZ157(s1Q)
		if s1T != want {
			t.Fatalf("reconstructed [[s_1]]_t does not match [[s_1]]_q reduced mod 157")
		}
	})
}

// TestDealKeysDetectsTamperedShare mirrors
// TestDealPreSigDetectsTamperedShare for DealKeys's shares.
func TestDealKeysDetectsTamperedShare(t *testing.T) {
	const threshold, numShares = 2, 5

	_, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	shares := make([]fields.ZQ, numShares)
	for i, k := range keys {
		shares[i] = k.s1Q[0]
	}
	shares[1] = shares[1].Add(shares[1].FromUint(1)) // corrupt party 1's share

	if _, err := ss.Reconstruct(shares, threshold, numShares); err == nil {
		t.Fatalf("expected Reconstruct to detect the tampered share, got no error")
	}
}

// TestDealPreSig deals preprocessing state for a set of parties and checks:
//  1. every field DealPreSig distributes is a valid (threshold, numShares)
//     Shamir sharing (all numShares shares lie on one degree-(threshold-1)
//     polynomial, per Reconstruct's built-in consistency check);
//  2. the reconstructed y matches the y that DealPreSig also returns
//     directly;
//  3. the reconstructed lookup tables match buildTableW/buildTableZ run
//     directly on the dealt w0/y and the reconstructed masks - i.e. the
//     tables were both shared correctly and rotated by the right mask.
//  4. each party's double-shared mask (h/h_double) reconstructs to the same
//     secret at both degree threshold and degree 2*threshold;
//  5. each party's keyShares reconstruct to that party's own key;
//  6. each party's u reconstructs (i.e. is a valid degree-threshold sharing).
func TestDealPreSig(t *testing.T) {
	const threshold, numShares = 2, 5

	pk, _, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	preSign, w0Q, yQ, err := DealPreSig(threshold, numShares, pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}
	if len(preSign) != numShares {
		t.Fatalf("expected %d preprocessing states, got %d", numShares, len(preSign))
	}

	// Split each party's PreprocessingState into per-field slices so they
	// can be fed to the reconstruct* helpers above.
	yQShares := make([]VecL[fields.ZQ], numShares)
	maskYShares := make([]VecL[fields.Z157], numShares)
	lutYShares := make([]LutL[fields.F2_8], numShares)
	w1Shares := make([]VecK[fields.ZQ], numShares)
	maskWShares := make([]VecK[fields.Z157], numShares)
	lutWShares := make([]LutK[fields.F2_8], numShares)
	seedShares := make([]fields.F2_128, numShares)
	for i, p := range preSign {
		yQShares[i] = p.yQ
		maskYShares[i] = VecL[fields.Z157](p.maskY)
		lutYShares[i] = LutL[fields.F2_8](p.lutY)
		w1Shares[i] = p.w1
		maskWShares[i] = VecK[fields.Z157](p.maskW)
		lutWShares[i] = LutK[fields.F2_8](p.lutW)
		seedShares[i] = p.seed
	}

	gotYQ, err := utils.ReconstructVecL(yQShares, threshold, numShares)
	if err != nil {
		t.Fatalf("reconstructing [[y]]_q shares: %v", err)
	}
	maskY, err := utils.ReconstructVecL(maskYShares, threshold, numShares)
	if err != nil {
		t.Fatalf("reconstructing [[mask_y]]_t shares: %v", err)
	}
	gotLutY, err := reconstructLutL(lutYShares, threshold, numShares)
	if err != nil {
		t.Fatalf("reconstructing lutY shares: %v", err)
	}
	if _, err := utils.ReconstructVecK(w1Shares, threshold, numShares); err != nil {
		t.Fatalf("reconstructing [[w_1]]_q shares: %v", err)
	}
	maskW, err := utils.ReconstructVecK(maskWShares, threshold, numShares)
	if err != nil {
		t.Fatalf("reconstructing [[mask_w]]_t shares: %v", err)
	}
	gotLutW, err := reconstructLutK(lutWShares, threshold, numShares)
	if err != nil {
		t.Fatalf("reconstructing lutW shares: %v", err)
	}
	if _, err := ss.Reconstruct(seedShares, threshold, numShares); err != nil {
		t.Fatalf("reconstructing seed shares: %v", err)
	}

	t.Run("yQ shares reconstruct to the dealt y", func(t *testing.T) {
		if gotYQ != yQ {
			t.Fatalf("reconstructed y does not match the y DealPreSig returned")
		}
	})

	t.Run("lutY shares reconstruct to the table built from y and maskY", func(t *testing.T) {
		// Also exercises that the per-row 1/0 entries were written to
		// (i + maskY[j]) mod t rather than to i.
		want := buildTableZ(threshold, numShares, yQ, maskY)
		if gotLutY != want {
			t.Fatalf("reconstructed lutY does not match buildTableZ(y, maskY)")
		}
	})

	t.Run("lutW shares reconstruct to the table built from w0 and maskW", func(t *testing.T) {
		want := buildTableW(threshold, numShares, w0Q, maskW)
		if gotLutW != want {
			t.Fatalf("reconstructed lutW does not match buildTableW(w0, maskW)")
		}
	})

	t.Run("h/h_double double-share the same secret per party", func(t *testing.T) {
		rT := ss.NewReconstructor[fields.F2_128](threshold, numShares)
		r2T := ss.NewReconstructor[fields.F2_128](2*threshold, numShares)
		for k := range numShares {
			hShares := make([]fields.F2_128, numShares)
			hDoubleShares := make([]fields.F2_128, numShares)
			for i, p := range preSign {
				hShares[i] = p.h[k]
				hDoubleShares[i] = p.h_double[k]
			}

			h, err := rT.Reconstruct(hShares)
			if err != nil {
				t.Fatalf("party %d: reconstructing h shares (degree threshold): %v", k, err)
			}
			hDouble, err := r2T.Reconstruct(hDoubleShares)
			if err != nil {
				t.Fatalf("party %d: reconstructing h_double shares (degree 2*threshold): %v", k, err)
			}
			if h != hDouble {
				t.Fatalf("party %d: h and h_double reconstruct to different secrets", k)
			}
		}
	})

	t.Run("keyShares reconstruct to the owner's own key", func(t *testing.T) {
		r := ss.NewReconstructor[fields.F2_128](threshold, numShares)
		for k := range numShares {
			shares := make([]fields.F2_128, numShares)
			for i, p := range preSign {
				shares[i] = p.keyShares[k]
			}

			got, err := r.Reconstruct(shares)
			if err != nil {
				t.Fatalf("party %d: reconstructing key shares: %v", k, err)
			}
			if got.Bytes() != preSign[k].key {
				t.Fatalf("party %d: reconstructed key does not match the owner's own key", k)
			}
		}
	})

	t.Run("u shares reconstruct", func(t *testing.T) {
		r := ss.NewReconstructor[fields.F2_128](threshold, numShares)
		for k := range numShares {
			shares := make([]fields.F2_128, numShares)
			for i, p := range preSign {
				shares[i] = p.u[k]
			}

			if _, err := r.Reconstruct(shares); err != nil {
				t.Fatalf("party %d: reconstructing u shares: %v", k, err)
			}
		}
	})
}

// TestDealPreSigDetectsTamperedShare checks that corrupting a single party's
// share is caught by Reconstruct's cross-share consistency check, i.e. the
// shares really do lie on a Shamir polynomial rather than being independent
// random values.
func TestDealPreSigDetectsTamperedShare(t *testing.T) {
	const threshold, numShares = 2, 5

	pk, _, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	preSign, _, _, err := DealPreSig(threshold, numShares, pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}

	shares := make([]fields.ZQ, numShares)
	for i, p := range preSign {
		shares[i] = p.yQ[0]
	}
	shares[1] = shares[1].Add(shares[1].FromUint(1)) // corrupt party 1's share

	if _, err := ss.Reconstruct(shares, threshold, numShares); err == nil {
		t.Fatalf("expected Reconstruct to detect the tampered share, got no error")
	}
}

// TestBuildTableZRotatesEachRowByItsMask checks the rotation added to
// buildTableZ in isolation: row j of the masked table must equal row j of
// the unrotated (mask=0) table, cyclically shifted by mask[j] positions.
// Comparing against an unrotated baseline (rather than recomputing the
// pass/fail formula in the test) keeps this test independent of the range
// check's own semantics.
// (parameter named tt, not the usual t: the package already has a top-level
// constant named t, the lookup table width, used below.)
func TestBuildTableZRotatesEachRowByItsMask(tt *testing.T) {
	var y VecL[fields.ZQ]
	for j := range y {
		y[j] = fields.ZQ(0).FromUint(uint32(j*12345) % fields.Q)
	}

	var zeroMask VecL[fields.Z157]
	baseline := buildTableZ(2, 4, y, zeroMask)

	var mask VecL[fields.Z157]
	for j := range mask {
		mask[j] = fields.Z157(0).FromUint(uint32((j*37 + 5) % t))
	}
	rotated := buildTableZ(2, 4, y, mask)

	for j := range L * N {
		r := int(mask[j])
		for i := range t {
			pos := (i + r) % t
			if rotated[j][pos] != baseline[j][i] {
				tt.Fatalf("row %d: rotated[%d]=%v, want baseline[%d]=%v (mask=%d)",
					j, pos, rotated[j][pos], i, baseline[j][i], r)
			}
		}
	}
}

// TestBuildTableWRotatesEachRowByItsMask mirrors
// TestBuildTableZRotatesEachRowByItsMask for buildTableW/maskW. (Also named
// tt for the same reason as above.)
func TestBuildTableWRotatesEachRowByItsMask(tt *testing.T) {
	var w0 VecK[fields.ZQ]
	for j := range w0 {
		w0[j] = fields.ZQ(0).FromUint(uint32(j*6789) % fields.Q)
	}

	var zeroMask VecK[fields.Z157]
	baseline := buildTableW(2, 4, w0, zeroMask)

	var mask VecK[fields.Z157]
	for j := range mask {
		mask[j] = fields.Z157(0).FromUint(uint32((j*41 + 3) % t))
	}
	rotated := buildTableW(2, 4, w0, mask)

	for j := range K * N {
		r := int(mask[j])
		for i := range t {
			pos := (i + r) % t
			if rotated[j][pos] != baseline[j][i] {
				tt.Fatalf("row %d: rotated[%d]=%v, want baseline[%d]=%v (mask=%d)",
					j, pos, rotated[j][pos], i, baseline[j][i], r)
			}
		}
	}
}
