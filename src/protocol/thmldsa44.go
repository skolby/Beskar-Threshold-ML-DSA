package protocol

import (
	"io"

	"github.com/cloudflare/circl/xof"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	"t-mldsa/src/fields"
	"t-mldsa/src/protocol/internal/wire"
	ss "t-mldsa/src/secretsharing"
	"t-mldsa/src/utils"
)

type Round1State struct {
	msg []byte
}

// cTilde is kept as bytes, not the derived challenge polynomial, since the
// latter is internal to mldsa44 - mirrors FinalizeSignature, which also
// takes c as [CTildeSize]byte and re-derives the polynomial itself.
type Round2State struct {
	cTilde [mldsa44.CTildeSize]byte // c~ = H(mu || w1)
	z      VecL[fields.ZQ]          // [[z]]_q = [[c * s_1]]_q + [[y]]_q, this party's share
}

// cTilde is carried forward from Round2State so Finalize can hand it to
// mldsa44.FinalizeSignature once z is reconstructed.
type Round3State struct {
	cTilde [mldsa44.CTildeSize]byte
}

type Round1Message struct {
	// Opening [[w_1]]_q, compressed 4-to-1 via utils.CompressVecK44 before
	// sending - see Round1's doc comment.
	w1 utils.VecKCompressed
}

type Round2Message struct {
	iW   VecK[fields.Z157] // [[i_w]]_t = [[c * -s_2]]_t + beta + [[mask_w]]_t
	iZ   VecL[fields.Z157] // [[i_z]]_t = [[c * s_1]]_t + beta + [[mask_y]]_t
	seed fields.F2_128     // [[seed]], this party's share, opened for the random linear comb.
}

type Round3Message struct {
	kPrime      []fields.F2_128 // k'_i = b * u_i + h_double_i, one entry per party
	keyOpenings []fields.F2_128 // h_i + keyShares_i, one entry per party
	ctxt        []byte          // ciphertext of this party's share of z_j
}

// Take in state ( preprocessing ([w_1], [y], LUT), [s]_t, [e]_t, [s]) and msg
//
// w_1's coefficients are known to lie in [0, w1Base), so each party's share of w_1 is
// compressed 4-to-1 before opening it.
func Round1(keyState KeyState, preSign PreprocessingState, msg []byte) (error, Round1State, Round1Message) {
	var r1State Round1State
	var r1Msg Round1Message
	r1State.msg = msg
	r1Msg.w1 = utils.CompressVecK44(preSign.w1)
	// Open w_1
	return nil, r1State, r1Msg
}

// Input, first round messages and state
func Round2(keyState KeyState, preSign PreprocessingState, r1State Round1State, r1Msg []Round1Message) (error, Round2State, Round2Message) {
	// Reconstruct compressed w_1, then decompress back to its full K*N
	// coordinates (see Round1's doc comment).
	w1Shares := make([]utils.VecKCompressed, keyState.numShares)
	for i, m := range r1Msg {
		w1Shares[i] = m.w1
	}
	w1Compressed, err := utils.ReconstructVecKCompressed(w1Shares, keyState.threshold, keyState.numShares)
	if err != nil {
		return err, Round2State{}, Round2Message{}
	}
	w1 := utils.DecompressVecK44(w1Compressed)

	// compute challenge
	cTilde, chal := mldsa44.ComputeChallenge(keyState.pk, utils.FromFieldElementK(w1), func(w io.Writer) {
		_, _ = w.Write(r1State.msg)
	})

	// [[z]]_q = [[c * s_1]]_q + [[y]]_q
	cS1 := utils.MulConstVecL(chal, keyState.s1Q)
	z := utils.AddVecL(cS1, preSign.yQ)

	// compute C [s]_t, C [-e]_t for LUT
	cCanon := utils.CanonicalizeChallenge(chal) // C, rounded through Z157 and lifted back to ZQ
	s1TQ := utils.ConvertVecLZ157oQ(keyState.s1T)
	s2TQ := utils.ConvertVecKZ157oQ(keyState.s2T) // keyState.s2T is [[-s_2]]_t
	cSt := utils.MulConstVecL(cCanon, s1TQ)
	cEt := utils.MulConstVecK(cCanon, s2TQ)

	// [[i_z]]_t = [[c * s_1]]_t + beta + [[mask_y]]_t, [[i_w]]_t = [[c * -s_2]]_t + beta + [[mask_w]]_t
	//
	// The +beta term aligns this with buildTableZ/buildTableW's indexing.
	betaZ157 := fields.Z157(0).FromUint(uint32(beta))
	iZ := utils.AddVecL(utils.AddConstVecL(utils.ConvertVecLQoZ157(cSt), betaZ157), preSign.maskY)
	iW := utils.AddVecK(utils.AddConstVecK(utils.ConvertVecKQoZ157(cEt), betaZ157), preSign.maskW)

	// Send seed for random linear comb.
	return nil, Round2State{cTilde: cTilde, z: z}, Round2Message{iW: iW, iZ: iZ, seed: preSign.seed}
}

func Round3(keyState KeyState, preSign PreprocessingState, r2State Round2State, r2Msg []Round2Message) (error, Round3State, Round3Message) {
	// Reconstruct i_w, i_z, and seed
	iWShares := make([]VecK[fields.Z157], keyState.numShares)
	iZShares := make([]VecL[fields.Z157], keyState.numShares)
	seedShares := make([]fields.F2_128, keyState.numShares)
	for i, m := range r2Msg {
		iWShares[i] = m.iW
		iZShares[i] = m.iZ
		seedShares[i] = m.seed
	}
	iW, err := utils.ReconstructVecK(iWShares, keyState.threshold, keyState.numShares)
	if err != nil {
		return err, Round3State{}, Round3Message{}
	}
	iZ, err := utils.ReconstructVecL(iZShares, keyState.threshold, keyState.numShares)
	if err != nil {
		return err, Round3State{}, Round3Message{}
	}
	seed, err := ss.Reconstruct(seedShares, keyState.threshold, keyState.numShares)
	if err != nil {
		return err, Round3State{}, Round3Message{}
	}
	// Get LUT shares, based on i_w, i_z.
	var bZ VecL[fields.F2_8]
	for j := range L * N {
		bZ[j] = preSign.lutY[j][int(iZ[j])]
	}
	var bW VecK[fields.F2_8]
	for j := range K * N {
		bW[j] = preSign.lutW[j][int(iW[j])]
	}

	// Expand the reconstructed seed into a SHAKE128 XOF - drawn from to
	// sample the random linear combination's F2_128 coefficients.
	seedBytes := seed.Bytes()
	rng := xof.SHAKE128.New()
	_, _ = rng.Write(seedBytes[:])
	var prng io.Reader = rng

	// Random linear comb
	b := utils.RandLinComb(prng, bZ, bW)

	// Mult and open k_j': b times party i's u share, masked by party i's
	// degree-2*threshold h_double share for opening. Separately, mask party
	// i's keyShares entry with party i's degree-threshold h share, also for
	// opening.
	kPrime := make([]fields.F2_128, keyState.numShares)
	keyOpenings := make([]fields.F2_128, keyState.numShares)
	for i := range keyState.numShares {
		kPrime[i] = b.Mult(preSign.u[i]).Add(preSign.h_double[i])
		keyOpenings[i] = preSign.h[i].Add(preSign.keyShares[i])
	}

	// Encrypt and send opening of z_j
	zBytes := wire.PackVecL(r2State.z)
	ctxt, err := utils.Encrypt(preSign.key[:], zBytes)
	if err != nil {
		return err, Round3State{}, Round3Message{}
	}

	return nil, Round3State{cTilde: r2State.cTilde}, Round3Message{kPrime: kPrime, keyOpenings: keyOpenings, ctxt: ctxt}
}

func Finalize(keyState KeyState, r3State Round3State, r3Msg []Round3Message) (error, []byte) {
	// Attempt to decrypt shares, abort if any fail. For each party j,
	// kPrime[j]/keyOpenings[j] carry a key which potentially allows decrypting their share of z.
	kPrimeReconstructor := ss.NewReconstructor[fields.F2_128](2*keyState.threshold, keyState.numShares)
	keyOpeningReconstructor := ss.NewReconstructor[fields.F2_128](keyState.threshold, keyState.numShares)

	zShares := make([]VecL[fields.ZQ], keyState.numShares)
	for j := range keyState.numShares {
		kPrimeShares := make([]fields.F2_128, keyState.numShares)
		keyOpeningShares := make([]fields.F2_128, keyState.numShares)
		for i, m := range r3Msg {
			kPrimeShares[i] = m.kPrime[j]
			keyOpeningShares[i] = m.keyOpenings[j]
		}

		kPrime, err := kPrimeReconstructor.Reconstruct(kPrimeShares)
		if err != nil {
			return err, nil
		}
		keyOpening, err := keyOpeningReconstructor.Reconstruct(keyOpeningShares)
		if err != nil {
			return err, nil
		}
		candidateKey := kPrime.Add(keyOpening).Bytes()

		zBytes, err := utils.Decrypt(candidateKey[:], r3Msg[j].ctxt)
		if err != nil {
			return err, nil
		}
		zShares[j], err = wire.UnpackVecL(zBytes)
		if err != nil {
			return err, nil
		}
	}

	// Reconstruct z
	z, err := utils.ReconstructVecL(zShares, keyState.threshold, keyState.numShares)
	if err != nil {
		return err, nil
	}

	// Post-process for final sig.
	sig, err := mldsa44.FinalizeSignature(keyState.pk, r3State.cTilde, utils.FromFieldElementL(z))
	if err != nil {
		return err, nil
	}
	return nil, sig
}
