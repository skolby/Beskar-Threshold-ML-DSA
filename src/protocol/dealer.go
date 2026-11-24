package protocol

// Artifically produce preprocessed inputs to give starting state of the online phase
// Warning: This code is not constant-time and should not be used in production. It is only for testing the protocol.

import (
	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	hooks "t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	"t-mldsa/src/fields"
	ss "t-mldsa/src/secretsharing"
	"t-mldsa/src/utils"
)

const (
	N      = utils.N
	K      = utils.K
	L      = utils.L
	t      = utils.TWidth
	beta   = 78
	gamma1 = 1 << 17
	gamma2 = 95232
)

// VecL, VecK, LutL and LutK alias utils' definitions rather than redeclaring
// them here - they need to live in utils so utils' own vector helpers
// (ShareVecL, ReconstructVecL, ToFieldElementL, etc., in vec.go) can take
// them directly without utils importing protocol (which would cycle back,
// since protocol imports utils for those helpers, plus encryption).
// Aliasing keeps every existing VecL/VecK/LutL/LutK reference in this
// package working unchanged.
type VecL[T fields.FieldElement[T]] = utils.VecL[T]
type VecK[T fields.FieldElement[T]] = utils.VecK[T]

type LutL[T fields.FieldElement[T]] = utils.LutL[T]
type LutK[T fields.FieldElement[T]] = utils.LutK[T]

type KeyState struct {
	partyID   int
	threshold int
	numShares int
	pk        *mldsa44.PublicKey
	s1Q       VecL[fields.ZQ]   // [[s_1]]_q
	s1T       VecL[fields.Z157] // [[s_1]]_t
	s2T       VecK[fields.Z157] // [[-s_2]]_t
}

type PreprocessingState struct {
	yQ    VecL[fields.ZQ]         // [[y]]_q
	maskY [(L * N)]fields.Z157    // [[mask_y]]_t
	lutY  [(L * N)][t]fields.F2_8 // lookup tables for y values

	w1    VecK[fields.ZQ]         // [[w_1]]_q
	maskW [(K * N)]fields.Z157    // [[mask_w]]_t
	lutW  [(K * N)][t]fields.F2_8 // lookup tables for w values

	seed fields.F2_128 // [[seed]], this party's share of a random F2_128 element

	u []fields.F2_128 // [[u_j]] of degree threshold
	// Double sharing of mask [DN'07] style, one share for each party.
	h        []fields.F2_128 // [[h_j]] of degree threshold
	h_double []fields.F2_128 // ⟨h_j⟩ of degree 2 * threshold

	key       [16]byte        // this party's own key, in the clear
	keyShares []fields.F2_128 // [[key_j]] of every party's key
}

// Runs key generation and shares the resulting secret key material across
// numShares parties, one KeyState per party. This includes:
// - [[s_1]]_q
// - [[s_1]]_t
// - [[-s_2]]_t
func DealKeys(threshold int, numShares int) (*mldsa44.PublicKey, []KeyState, error) {
	// Shares of w_0 and sk are produced and sent to the parties.
	// parties also need to be given t0 from sk.
	pk, s1, s2, err := hooks.DealerGenerateKeys()
	if err != nil {
		return nil, nil, err
	}
	s1.Normalize()
	s2.Normalize()

	s1Q := utils.ToFieldElementL(s1)
	s1T := utils.ConvertVecLQoZ157(s1Q)
	// Negated before sharing - signing needs -s_2, not s_2 itself.
	s2T := utils.NegVecK(utils.ConvertVecKQoZ157(utils.ToFieldElementK(s2)))

	shS1Q := utils.ShareVecL(s1Q, threshold, numShares)
	shS1T := utils.ShareVecL(s1T, threshold, numShares)
	shS2T := utils.ShareVecK(s2T, threshold, numShares)

	keys := make([]KeyState, numShares)
	for i := range numShares {
		keys[i] = KeyState{
			partyID:   i + 1, // parties are indexed from 1, matching the Shamir x-coordinates Share uses
			threshold: threshold,
			numShares: numShares,
			pk:        pk,
			s1Q:       shS1Q[i],
			s1T:       shS1T[i],
			s2T:       shS2T[i],
		}
	}

	return pk, keys, nil
}

/*
Produces preprocessing state for each party with respect to the given public key.
This includes:
  - [[y]]_q
  - [[mask_y]]_t
  - [[w_1]]_t
  - [[mask_w]]_t
  - Shares of lookup tables for y and w0
  - [[seed]], a shared random F2_128 element
  - One shared random F2_128 element per party (u)
  - One [DN'07]-style double-shared random F2_128 mask per party (h/h_double)
  - One random 16-byte key per party, given in the clear to its owner and
    Shamir-shared to every party, owner included (key/keyShares)

Also returns the dealt (unshared) w0 and y in the ZQ field, purely so tests
can check the shared lookup tables against a directly-computed table.
*/
func DealPreSig(threshold int, numShares int, pk *mldsa44.PublicKey) ([]PreprocessingState, VecK[fields.ZQ], VecL[fields.ZQ], error) {
	// Each party should be given one preprocessing state
	var preSign []PreprocessingState
	preSign = make([]PreprocessingState, numShares)

	// Run local pre-signing to get w0, w1, y
	w0, w1, y := mldsa44.DealerPreSign(pk)

	yQ := utils.ToFieldElementL(y)
	w0Q := utils.ToFieldElementK(w0)
	w1Q := utils.ToFieldElementK(w1)

	// Sample fresh masks used to blind the range-check lookup tables
	maskY, err := utils.RandVecL[fields.Z157]()
	if err != nil {
		return nil, VecK[fields.ZQ]{}, VecL[fields.ZQ]{}, err
	}
	maskW, err := utils.RandVecK[fields.Z157]()
	if err != nil {
		return nil, VecK[fields.ZQ]{}, VecL[fields.ZQ]{}, err
	}

	// Compute lookup tables for w0 and y, rotated by the sampled masks
	lutW := buildTableW(threshold, numShares, w0Q, maskW)
	lutY := buildTableZ(threshold, numShares, yQ, maskY)

	// Share y
	shYQ := utils.ShareVecL(yQ, threshold, numShares)
	shMaskY := utils.ShareVecL(maskY, threshold, numShares)

	// Share w1
	shW1 := utils.ShareVecK(w1Q, threshold, numShares)
	shMaskW := utils.ShareVecK(maskW, threshold, numShares)

	// Share lookup tables
	shLutY := utils.ShareLutL(lutY, threshold, numShares)
	shLutW := utils.ShareLutK(lutW, threshold, numShares)

	// Sample and share a random seed
	seed, err := fields.F2_128{}.Rand()
	if err != nil {
		return nil, VecK[fields.ZQ]{}, VecL[fields.ZQ]{}, err
	}
	shSeed := ss.Share(seed, threshold, numShares)

	// Sample and share one random F2_128 element per party: uByOwner[k]
	// shares the element contributed by party k at degree threshold.
	uByOwner := make([][]fields.F2_128, numShares)
	for k := range numShares {
		uk, err := fields.F2_128{}.Rand()
		if err != nil {
			return nil, VecK[fields.ZQ]{}, VecL[fields.ZQ]{}, err
		}
		uByOwner[k] = ss.Share(uk, threshold, numShares)
	}

	// Sample and double-share one random F2_128 mask per party [DN'07]
	// style: hByOwner[k] shares the mask contributed by party k at degree
	// threshold (needs threshold+1 shares to reconstruct), hDoubleByOwner[k]
	// shares that very same secret at degree 2*threshold (needs 2*threshold+1
	// shares to reconstruct - hence numShares must exceed 2*threshold).
	hByOwner := make([][]fields.F2_128, numShares)
	hDoubleByOwner := make([][]fields.F2_128, numShares)
	for k := range numShares {
		hk, err := fields.F2_128{}.Rand()
		if err != nil {
			return nil, VecK[fields.ZQ]{}, VecL[fields.ZQ]{}, err
		}
		hByOwner[k] = ss.Share(hk, threshold, numShares)
		hDoubleByOwner[k] = ss.Share(hk, 2*threshold, numShares)
	}

	// Sample one random 16-byte key per party. The owner gets it directly
	// (in the clear); every party, owner included, also gets a Shamir share
	// of it - the group can reconstruct it, and decrypt whatever was
	// encrypted under it, even if the owner won't reveal it.
	keyByOwner := make([][16]byte, numShares)
	shKeyByOwner := make([][]fields.F2_128, numShares)
	for k := range numShares {
		key, err := fields.F2_128{}.Rand()
		if err != nil {
			return nil, VecK[fields.ZQ]{}, VecL[fields.ZQ]{}, err
		}
		keyByOwner[k] = key.Bytes()
		shKeyByOwner[k] = ss.Share(key, threshold, numShares)
	}

	// Transpose every one of the above by owner -> by recipient in one pass,
	// so e.g. shU[i] is party i's share of every party's contributed u
	// element.
	shU := make([][]fields.F2_128, numShares)
	shH := make([][]fields.F2_128, numShares)
	shHDouble := make([][]fields.F2_128, numShares)
	shKey := make([][]fields.F2_128, numShares)
	for i := range numShares {
		shU[i] = make([]fields.F2_128, numShares)
		shH[i] = make([]fields.F2_128, numShares)
		shHDouble[i] = make([]fields.F2_128, numShares)
		shKey[i] = make([]fields.F2_128, numShares)
		for k := range numShares {
			shU[i][k] = uByOwner[k][i]
			shH[i][k] = hByOwner[k][i]
			shHDouble[i][k] = hDoubleByOwner[k][i]
			shKey[i][k] = shKeyByOwner[k][i]
		}
	}

	for i := range numShares {
		preSign[i] = PreprocessingState{
			yQ:    shYQ[i],
			maskY: shMaskY[i],
			lutY:  shLutY[i],

			w1:    shW1[i],
			maskW: shMaskW[i],
			lutW:  shLutW[i],

			seed: shSeed[i],

			u: shU[i],

			h:        shH[i],
			h_double: shHDouble[i],

			key:       keyByOwner[i],
			keyShares: shKey[i],
		}
	}

	return preSign, w0Q, yQ, nil
}

// buildTableZ builds the range-check lookup table for y, rotated per
// coordinate by maskY: the value computed for offset i is stored at
// position (i + maskY[j]) mod t, instead of at i directly.
func buildTableZ(threshold int, numShares int, y VecL[fields.ZQ], maskY VecL[fields.Z157]) LutL[fields.F2_8] {
	var lut LutL[fields.F2_8]
	for j := range L * N {
		r := int(maskY[j])
		for i := range t {
			yi := int(y[j]) + i - beta
			pos := (i + r) % t
			// ||yi||_∞ <= γ1 − β
			if (yi < gamma1-beta) || (yi > int(fields.Q)-gamma1+beta) {
				lut[j][pos] = fields.F2_8(0)
			} else {
				lut[j][pos] = fields.F2_8(1)
			}
		}
	}
	return lut
}

// buildTableW builds the range-check lookup table for w0, rotated per
// coordinate by maskW: the value computed for offset i is stored at
// position (i + maskW[j]) mod t, instead of at i directly.
func buildTableW(threshold int, numShares int, w0 VecK[fields.ZQ], maskW VecK[fields.Z157]) LutK[fields.F2_8] {
	var lut LutK[fields.F2_8]
	for j := range K * N {
		r := int(maskW[j])
		for i := range t {
			w0i := int(w0[j]) + i - beta
			pos := (i + r) % t
			// ||w0i||_∞ <= γ2 − β
			if (w0i < gamma2-beta) || (w0i > int(fields.Q)-gamma2+beta) {
				lut[j][pos] = fields.F2_8(0)
			} else {
				lut[j][pos] = fields.F2_8(1)
			}
		}
	}
	return lut
}
