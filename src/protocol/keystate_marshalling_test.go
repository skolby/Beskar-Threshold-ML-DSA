package protocol

import (
	"bytes"
	"encoding/gob"
	"reflect"
	"testing"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
)

// keyStatesEqual reports whether a and b hold the same KeyState content.
// Not a plain reflect.DeepEqual(a, b): KeyState.pk is a *mldsa44.PublicKey,
// and DealerGenerateKeys's original pk vs. one reconstructed by
// PublicKey.Unpack (as GobDecode does) cache some fields - e.g. the derived
// matrix A - via different but mathematically-equivalent internal
// representations, so DeepEqual on the dereferenced struct is not the
// right equality check even though both verify signatures identically
// (confirmed separately: Verify accepts a signature under either). Pack()
// byte-equality is pk's actual, well-defined equality - the same
// public key, canonically encoded - regardless of internal caching.
func keyStatesEqual(a, b KeyState) bool {
	if a.partyID != b.partyID || a.threshold != b.threshold || a.numShares != b.numShares {
		return false
	}
	if a.s1Q != b.s1Q || a.s1T != b.s1T || a.s2T != b.s2T {
		return false
	}
	if (a.pk == nil) != (b.pk == nil) {
		return false
	}
	if a.pk == nil {
		return true
	}
	var aBuf, bBuf [mldsa44.PublicKeySize]byte
	a.pk.Pack(&aBuf)
	b.pk.Pack(&bBuf)
	return aBuf == bBuf
}

// TestKeyStateAccessors checks PartyID/Threshold/NumShares return exactly
// what DealKeys assigned - the field values a network layer needs without
// reaching into KeyState's unexported fields.
func TestKeyStateAccessors(t *testing.T) {
	const threshold, numShares = 2, 5

	_, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	for i, k := range keys {
		if got, want := k.PartyID(), i+1; got != want {
			t.Fatalf("keys[%d].PartyID() = %d, want %d", i, got, want)
		}
		if got, want := k.Threshold(), threshold; got != want {
			t.Fatalf("keys[%d].Threshold() = %d, want %d", i, got, want)
		}
		if got, want := k.NumShares(), numShares; got != want {
			t.Fatalf("keys[%d].NumShares() = %d, want %d", i, got, want)
		}
	}
}

// TestKeyStateGobEncodeDecodeRoundTrip checks that calling GobEncode then
// GobDecode directly recovers every field of the original KeyState exactly,
// for every party DealKeys produces. reflect.DeepEqual works here (rather
// than ==) both because KeyState holds a slice-shaped VecL/VecK... no,
// those are fixed-size arrays and would compare fine with == too - the
// actual reason is the *mldsa44.PublicKey field, a pointer DealKeys gives
// every party the *same* instance of but GobDecode reconstructs as a fresh
// pointer with equal (DeepEqual-comparable) pointee content.
func TestKeyStateGobEncodeDecodeRoundTrip(t *testing.T) {
	const threshold, numShares = 2, 5

	_, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	for i, want := range keys {
		packed, err := want.GobEncode()
		if err != nil {
			t.Fatalf("keys[%d].GobEncode failed: %v", i, err)
		}

		var got KeyState
		if err := got.GobDecode(packed); err != nil {
			t.Fatalf("GobDecode(keys[%d]) failed: %v", i, err)
		}

		if !keyStatesEqual(got, want) {
			t.Fatalf("GobDecode(GobEncode(keys[%d])) != keys[%d]", i, i)
		}
	}
}

// TestKeyStateGobRoundTripsThroughAnExportedField mirrors
// fields.TestF2_128GobRoundTripsThroughAnExportedField: the actual intended
// use case is a KeyState embedded as an exported field of one of package
// network's own messages, round-tripped through a real gob.Encoder/Decoder
// pair rather than by calling GobEncode/GobDecode directly.
func TestKeyStateGobRoundTripsThroughAnExportedField(t *testing.T) {
	const threshold, numShares = 2, 5

	_, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	type bundle struct {
		Key KeyState
	}
	want := bundle{Key: keys[0]}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(want); err != nil {
		t.Fatalf("gob Encode failed: %v", err)
	}

	var got bundle
	if err := gob.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("gob Decode failed: %v", err)
	}

	if !keyStatesEqual(got.Key, want.Key) {
		t.Fatalf("gob round trip through an exported field changed the KeyState")
	}
}

// TestKeyStateGobDecodeRejectsGarbage checks GobDecode returns an error -
// not a panic - for input that isn't a valid gob-encoded keyStateShadow.
func TestKeyStateGobDecodeRejectsGarbage(t *testing.T) {
	var k KeyState
	for _, data := range [][]byte{nil, []byte("not gob data at all"), {0xff, 0x00, 0x01}} {
		if err := k.GobDecode(data); err == nil {
			t.Fatalf("GobDecode(%q) succeeded, want an error", data)
		}
	}
}

// TestKeyStateGobDecodeRejectsTruncatedValidGob checks that truncating an
// otherwise-valid encoding (rather than feeding in unrelated garbage) is
// also rejected, not silently accepted with zero-valued trailing fields.
func TestKeyStateGobDecodeRejectsTruncatedValidGob(t *testing.T) {
	const threshold, numShares = 2, 5

	_, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	packed, err := keys[0].GobEncode()
	if err != nil {
		t.Fatalf("GobEncode failed: %v", err)
	}

	var k KeyState
	if err := k.GobDecode(packed[:len(packed)-1]); err == nil {
		t.Fatalf("GobDecode(truncated data) succeeded, want an error")
	}
}

// TestPreprocessingStateGobEncodeDecodeRoundTrip mirrors
// TestKeyStateGobEncodeDecodeRoundTrip for PreprocessingState, including its
// numShares-length slice fields (u/h/h_double/keyShares) and large fixed
// lookup tables (lutY/lutW).
func TestPreprocessingStateGobEncodeDecodeRoundTrip(t *testing.T) {
	const threshold, numShares = 2, 5

	_, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	pk := keys[0].pk
	preSign, _, _, err := DealPreSig(threshold, numShares, pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}

	for i, want := range preSign {
		packed, err := want.GobEncode()
		if err != nil {
			t.Fatalf("preSign[%d].GobEncode failed: %v", i, err)
		}

		var got PreprocessingState
		if err := got.GobDecode(packed); err != nil {
			t.Fatalf("GobDecode(preSign[%d]) failed: %v", i, err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("GobDecode(GobEncode(preSign[%d])) != preSign[%d]", i, i)
		}
	}
}

// TestPreprocessingStateGobRoundTripsThroughAnExportedField mirrors
// TestKeyStateGobRoundTripsThroughAnExportedField for PreprocessingState.
func TestPreprocessingStateGobRoundTripsThroughAnExportedField(t *testing.T) {
	const threshold, numShares = 2, 5

	_, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	preSign, _, _, err := DealPreSig(threshold, numShares, keys[0].pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}

	type bundle struct {
		PreSign PreprocessingState
	}
	want := bundle{PreSign: preSign[0]}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(want); err != nil {
		t.Fatalf("gob Encode failed: %v", err)
	}

	var got bundle
	if err := gob.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("gob Decode failed: %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("gob round trip through an exported field changed the PreprocessingState")
	}
}

// TestPreprocessingStateGobDecodeRejectsGarbage mirrors
// TestKeyStateGobDecodeRejectsGarbage for PreprocessingState.
func TestPreprocessingStateGobDecodeRejectsGarbage(t *testing.T) {
	var p PreprocessingState
	for _, data := range [][]byte{nil, []byte("not gob data at all"), {0xff, 0x00, 0x01}} {
		if err := p.GobDecode(data); err == nil {
			t.Fatalf("GobDecode(%q) succeeded, want an error", data)
		}
	}
}
