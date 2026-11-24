package protocol

// keystate_marshalling.go adds accessors and gob marshalling for KeyState
// and PreprocessingState, so package network's leader can distribute each
// party's dealt key material and per-session preprocessing (dealer.go)
// over the wire. Separate from marshalling.go, which packs the round
// messages the real protocol rounds put on the wire - KeyState/
// PreprocessingState are never packed by Round1/Round2/Round3/Finalize
// themselves.
//
// Both types keep every field unexported (like Round1Message etc. -
// marshalling.go), so plain gob/json reflection can't marshal them
// directly: it only sees exported fields, and would silently encode
// nothing. Instead they implement gob.GobEncoder/GobDecoder over a private
// exported "shadow" struct - much less code than a hand-rolled codec, and
// fine here since, unlike round messages, this data is sent once per party
// per run, not on a latency-measured path. fields.F2_128 needed the same
// treatment one level down (its hi/lo are unexported too); see its
// GobEncode/GobDecode in src/fields/f_2_128.go.

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	"t-mldsa/src/fields"
)

// PartyID returns this KeyState's 1-indexed Shamir party index (the
// x-coordinate DealKeys assigned it, see dealer.go) - callers use this to
// place their own round message at the right slot (index PartyID()-1) in
// the slices Round2/Round3/Finalize expect.
func (k KeyState) PartyID() int { return k.partyID }

// Threshold returns the (t) in this KeyState's (threshold, numShares)
// Shamir sharing.
func (k KeyState) Threshold() int { return k.threshold }

// NumShares returns numShares - the total number of parties, and the
// length every r1Msg/r2Msg/r3Msg slice passed to Round2/Round3/Finalize
// must have.
func (k KeyState) NumShares() int { return k.numShares }

// keyStateShadow mirrors KeyState field-for-field, but exported so
// encoding/gob's reflection can see them. pk is carried as its packed byte
// encoding (mldsa44.PublicKey.Pack/Unpack) rather than embedding the
// pointer itself, so this doesn't depend on gob's default (reflection-
// based) handling of a type this package doesn't own.
type keyStateShadow struct {
	PartyID, Threshold, NumShares int
	PK                            [mldsa44.PublicKeySize]byte
	S1Q                           VecL[fields.ZQ]
	S1T                           VecL[fields.Z157]
	S2T                           VecK[fields.Z157]
}

// GobEncode implements gob.GobEncoder for KeyState.
func (k KeyState) GobEncode() ([]byte, error) {
	shadow := keyStateShadow{
		PartyID:   k.partyID,
		Threshold: k.threshold,
		NumShares: k.numShares,
		S1Q:       k.s1Q,
		S1T:       k.s1T,
		S2T:       k.s2T,
	}
	k.pk.Pack(&shadow.PK)

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shadow); err != nil {
		return nil, fmt.Errorf("protocol: gob-encoding KeyState: %w", err)
	}
	return buf.Bytes(), nil
}

// GobDecode implements gob.GobDecoder for KeyState. Needs a pointer
// receiver, per gob.GobDecoder's contract, so gob can write the decoded
// value back into the caller's variable.
func (k *KeyState) GobDecode(data []byte) error {
	var shadow keyStateShadow
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&shadow); err != nil {
		return fmt.Errorf("protocol: gob-decoding KeyState: %w", err)
	}

	pk := new(mldsa44.PublicKey)
	pk.Unpack(&shadow.PK)

	*k = KeyState{
		partyID:   shadow.PartyID,
		threshold: shadow.Threshold,
		numShares: shadow.NumShares,
		pk:        pk,
		s1Q:       shadow.S1Q,
		s1T:       shadow.S1T,
		s2T:       shadow.S2T,
	}
	return nil
}

// preprocessingStateShadow mirrors PreprocessingState field-for-field,
// exported for the same reason keyStateShadow is.
type preprocessingStateShadow struct {
	YQ    VecL[fields.ZQ]
	MaskY [L * N]fields.Z157
	LutY  [L * N][t]fields.F2_8

	W1    VecK[fields.ZQ]
	MaskW [K * N]fields.Z157
	LutW  [K * N][t]fields.F2_8

	Seed fields.F2_128

	U       []fields.F2_128
	H       []fields.F2_128
	HDouble []fields.F2_128

	Key       [16]byte
	KeyShares []fields.F2_128
}

// GobEncode implements gob.GobEncoder for PreprocessingState.
func (p PreprocessingState) GobEncode() ([]byte, error) {
	shadow := preprocessingStateShadow{
		YQ: p.yQ, MaskY: p.maskY, LutY: p.lutY,
		W1: p.w1, MaskW: p.maskW, LutW: p.lutW,
		Seed:      p.seed,
		U:         p.u,
		H:         p.h,
		HDouble:   p.h_double,
		Key:       p.key,
		KeyShares: p.keyShares,
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(shadow); err != nil {
		return nil, fmt.Errorf("protocol: gob-encoding PreprocessingState: %w", err)
	}
	return buf.Bytes(), nil
}

// GobDecode implements gob.GobDecoder for PreprocessingState.
func (p *PreprocessingState) GobDecode(data []byte) error {
	var shadow preprocessingStateShadow
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&shadow); err != nil {
		return fmt.Errorf("protocol: gob-decoding PreprocessingState: %w", err)
	}

	*p = PreprocessingState{
		yQ: shadow.YQ, maskY: shadow.MaskY, lutY: shadow.LutY,
		w1: shadow.W1, maskW: shadow.MaskW, lutW: shadow.LutW,
		seed:      shadow.Seed,
		u:         shadow.U,
		h:         shadow.H,
		h_double:  shadow.HDouble,
		key:       shadow.Key,
		keyShares: shadow.KeyShares,
	}
	return nil
}
