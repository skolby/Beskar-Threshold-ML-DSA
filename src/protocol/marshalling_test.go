package protocol

import (
	"testing"

	"t-mldsa/src/protocol/internal/wire"
)

// roundMessagesForMarshallingTests runs every party through Round1/Round2/
// Round3 far enough to produce one real instance of each message type -
// mirrors TestRoundFlow's setup, but only needs the first party's messages
// since these tests only care about Pack/Unpack round-tripping the
// resulting messages, not the protocol's cryptographic properties.
func roundMessagesForMarshallingTests(t *testing.T) (Round1Message, Round2Message, Round3Message) {
	t.Helper()
	const threshold, numShares = 2, 5
	msg := []byte("hello, threshold ML-DSA")

	pk, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	preSign, _, _, err := DealPreSig(threshold, numShares, pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}

	r1States := make([]Round1State, numShares)
	r1Msgs := make([]Round1Message, numShares)
	for i := range numShares {
		var err error
		err, r1States[i], r1Msgs[i] = Round1(keys[i], preSign[i], msg)
		if err != nil {
			t.Fatalf("party %d: Round1 failed: %v", i, err)
		}
	}

	r2States := make([]Round2State, numShares)
	r2Msgs := make([]Round2Message, numShares)
	for i := range numShares {
		var err error
		err, r2States[i], r2Msgs[i] = Round2(keys[i], preSign[i], r1States[i], r1Msgs)
		if err != nil {
			t.Fatalf("party %d: Round2 failed: %v", i, err)
		}
	}

	err, _, r3Msg := Round3(keys[0], preSign[0], r2States[0], r2Msgs)
	if err != nil {
		t.Fatalf("Round3 failed: %v", err)
	}

	return r1Msgs[0], r2Msgs[0], r3Msg
}

// TestPackUnpackRound1MessageRoundTrip checks that UnpackRound1Message
// recovers exactly what PackRound1Message packed, and that the encoding is
// exactly (K*N/4)*3 bytes long - Round1's w_1 is compressed 4-to-1 (see its
// doc comment) before PackVecKCompressed's own 3-bytes-per-coefficient
// encoding.
func TestPackUnpackRound1MessageRoundTrip(t *testing.T) {
	r1Msg, _, _ := roundMessagesForMarshallingTests(t)

	packed := PackRound1Message(r1Msg)
	wantLen := K * N / 4 * 3
	if len(packed) != wantLen {
		t.Fatalf("len(PackRound1Message(m)) = %d, want %d", len(packed), wantLen)
	}

	got, err := UnpackRound1Message(packed)
	if err != nil {
		t.Fatalf("UnpackRound1Message failed: %v", err)
	}
	if got != r1Msg {
		t.Fatalf("UnpackRound1Message(PackRound1Message(m)) != m")
	}
}

// TestUnpackRound1MessageRejectsWrongLength checks UnpackRound1Message
// returns an error, rather than panicking, on a byte slice that isn't
// exactly (K*N/4)*3 bytes long.
func TestUnpackRound1MessageRejectsWrongLength(t *testing.T) {
	if _, err := UnpackRound1Message(make([]byte, K*N/4*3-1)); err == nil {
		t.Fatalf("UnpackRound1Message(short data) succeeded, want an error")
	}
}

// TestPackUnpackRound2MessageRoundTrip checks that UnpackRound2Message
// recovers exactly what PackRound2Message packed, and that the encoding is
// exactly K*N + L*N + 16 bytes long (iW, iZ, and seed).
func TestPackUnpackRound2MessageRoundTrip(t *testing.T) {
	_, r2Msg, _ := roundMessagesForMarshallingTests(t)

	packed := PackRound2Message(r2Msg)
	wantLen := K*N + L*N + wire.F2_128ByteWidth
	if len(packed) != wantLen {
		t.Fatalf("len(PackRound2Message(m)) = %d, want %d", len(packed), wantLen)
	}

	got, err := UnpackRound2Message(packed)
	if err != nil {
		t.Fatalf("UnpackRound2Message failed: %v", err)
	}
	if got != r2Msg {
		t.Fatalf("UnpackRound2Message(PackRound2Message(m)) != m")
	}
}

// TestUnpackRound2MessageRejectsWrongLength mirrors
// TestUnpackRound1MessageRejectsWrongLength for Round2Message.
func TestUnpackRound2MessageRejectsWrongLength(t *testing.T) {
	wantLen := K*N + L*N + wire.F2_128ByteWidth
	if _, err := UnpackRound2Message(make([]byte, wantLen-1)); err == nil {
		t.Fatalf("UnpackRound2Message(short data) succeeded, want an error")
	}
}

// TestPackUnpackRound3MessageRoundTrip checks that UnpackRound3Message
// recovers exactly what PackRound3Message packed - kPrime, keyOpenings and
// ctxt each compared field-by-field, since Round3Message's slice fields
// make it non-comparable with ==.
func TestPackUnpackRound3MessageRoundTrip(t *testing.T) {
	_, _, r3Msg := roundMessagesForMarshallingTests(t)

	packed := PackRound3Message(r3Msg)
	got, err := UnpackRound3Message(packed)
	if err != nil {
		t.Fatalf("UnpackRound3Message failed: %v", err)
	}

	if len(got.kPrime) != len(r3Msg.kPrime) {
		t.Fatalf("len(got.kPrime) = %d, want %d", len(got.kPrime), len(r3Msg.kPrime))
	}
	for i := range r3Msg.kPrime {
		if got.kPrime[i] != r3Msg.kPrime[i] {
			t.Fatalf("kPrime[%d] = %+v, want %+v", i, got.kPrime[i], r3Msg.kPrime[i])
		}
	}

	if len(got.keyOpenings) != len(r3Msg.keyOpenings) {
		t.Fatalf("len(got.keyOpenings) = %d, want %d", len(got.keyOpenings), len(r3Msg.keyOpenings))
	}
	for i := range r3Msg.keyOpenings {
		if got.keyOpenings[i] != r3Msg.keyOpenings[i] {
			t.Fatalf("keyOpenings[%d] = %+v, want %+v", i, got.keyOpenings[i], r3Msg.keyOpenings[i])
		}
	}

	if string(got.ctxt) != string(r3Msg.ctxt) {
		t.Fatalf("ctxt = %v, want %v", got.ctxt, r3Msg.ctxt)
	}
}

// TestUnpackRound3MessageRejectsTruncatedData checks UnpackRound3Message
// returns an error, rather than panicking, on truncated data.
func TestUnpackRound3MessageRejectsTruncatedData(t *testing.T) {
	_, _, r3Msg := roundMessagesForMarshallingTests(t)
	packed := PackRound3Message(r3Msg)

	if _, err := UnpackRound3Message(packed[:len(packed)-1]); err == nil {
		t.Fatalf("UnpackRound3Message(truncated data) succeeded, want an error")
	}
}

// TestPackRound3MessageAppendsATrailerConsistentWithWirePackage cross-checks
// PackRound3Message against protocol/internal/wire directly: re-encoding
// the same three fields by hand via wire.PackF2_128Slice/wire.PackBytes
// must produce byte-for-byte the same result.
func TestPackRound3MessageAppendsATrailerConsistentWithWirePackage(t *testing.T) {
	_, _, r3Msg := roundMessagesForMarshallingTests(t)

	got := PackRound3Message(r3Msg)

	var want []byte
	want = wire.PackF2_128Slice(want, r3Msg.kPrime)
	want = wire.PackF2_128Slice(want, r3Msg.keyOpenings)
	want = wire.PackBytes(want, r3Msg.ctxt)

	if string(got) != string(want) {
		t.Fatalf("PackRound3Message(m) does not match the equivalent hand-built wire encoding")
	}
}
