package protocol

// Wire encoding for each round's message type, so a run of the protocol's
// communication cost can be measured directly (len(PackRoundNMessage(...)))
// rather than estimated from the Go struct layout. These live in package
// protocol, rather than protocol/internal/wire, since Round1Message/
// Round2Message/Round3Message keep their fields unexported; the actual byte
// encodings - both the fixed-size vector codecs (PackVecK, PackVecKZ157,
// PackVecLZ157) and Round3Message's length-prefixed framing - live in
// protocol/internal/wire. Each Pack/Unpack pair round-trips exactly - see
// marshalling_test.go.

import (
	"fmt"

	"t-mldsa/src/fields"
	"t-mldsa/src/protocol/internal/wire"
)

// PackRound1Message packs a Round1Message - the opened [[w_1]]_q, already
// compressed 4-to-1 by Round1 (see its doc comment) - into a byte slice,
// via wire.PackVecKCompressed.
func PackRound1Message(m Round1Message) []byte {
	return wire.PackVecKCompressed(m.w1)
}

// UnpackRound1Message is the inverse of PackRound1Message.
func UnpackRound1Message(data []byte) (Round1Message, error) {
	w1, err := wire.UnpackVecKCompressed(data)
	if err != nil {
		return Round1Message{}, fmt.Errorf("protocol: unpacking Round1Message: %w", err)
	}
	return Round1Message{w1: w1}, nil
}

// PackRound2Message packs a Round2Message as iW || iZ || seed - iW and iZ
// via wire's one-byte-per-coefficient Z157 encoding, seed via F2_128's own
// 16-byte encoding. All three fields have a fixed size, so no length
// prefixes are needed.
func PackRound2Message(m Round2Message) []byte {
	iw := wire.PackVecKZ157(m.iW)
	iz := wire.PackVecLZ157(m.iZ)
	seedBytes := m.seed.Bytes()

	out := make([]byte, 0, len(iw)+len(iz)+len(seedBytes))
	out = append(out, iw...)
	out = append(out, iz...)
	out = append(out, seedBytes[:]...)
	return out
}

// UnpackRound2Message is the inverse of PackRound2Message.
func UnpackRound2Message(data []byte) (Round2Message, error) {
	wantLen := K*N + L*N + wire.F2_128ByteWidth
	if len(data) != wantLen {
		return Round2Message{}, fmt.Errorf("protocol: expected %d bytes, got %d", wantLen, len(data))
	}

	iw, err := wire.UnpackVecKZ157(data[:K*N])
	if err != nil {
		return Round2Message{}, fmt.Errorf("protocol: unpacking Round2Message.iW: %w", err)
	}
	iz, err := wire.UnpackVecLZ157(data[K*N : K*N+L*N])
	if err != nil {
		return Round2Message{}, fmt.Errorf("protocol: unpacking Round2Message.iZ: %w", err)
	}
	var seedBytes [wire.F2_128ByteWidth]byte
	copy(seedBytes[:], data[K*N+L*N:])
	seed := fields.F2_128{}.FromBytes(seedBytes)

	return Round2Message{iW: iw, iZ: iz, seed: seed}, nil
}

// PackRound3Message packs a Round3Message as kPrime || keyOpenings || ctxt,
// each framed via protocol/internal/wire's length-prefixed encodings, since
// unlike Round1Message/Round2Message none of Round3Message's fields have a
// size fixed by the scheme parameters alone (kPrime/keyOpenings are sized
// by numShares, ctxt by AES-GCM's overhead over z's packed size).
func PackRound3Message(m Round3Message) []byte {
	var out []byte
	out = wire.PackF2_128Slice(out, m.kPrime)
	out = wire.PackF2_128Slice(out, m.keyOpenings)
	out = wire.PackBytes(out, m.ctxt)
	return out
}

// UnpackRound3Message is the inverse of PackRound3Message.
func UnpackRound3Message(data []byte) (Round3Message, error) {
	kPrime, rest, err := wire.UnpackF2_128Slice(data)
	if err != nil {
		return Round3Message{}, fmt.Errorf("protocol: unpacking Round3Message.kPrime: %w", err)
	}
	keyOpenings, rest, err := wire.UnpackF2_128Slice(rest)
	if err != nil {
		return Round3Message{}, fmt.Errorf("protocol: unpacking Round3Message.keyOpenings: %w", err)
	}
	ctxt, rest, err := wire.UnpackBytes(rest)
	if err != nil {
		return Round3Message{}, fmt.Errorf("protocol: unpacking Round3Message.ctxt: %w", err)
	}
	if len(rest) != 0 {
		return Round3Message{}, fmt.Errorf("protocol: %d trailing bytes after Round3Message", len(rest))
	}

	return Round3Message{kPrime: kPrime, keyOpenings: keyOpenings, ctxt: ctxt}, nil
}
