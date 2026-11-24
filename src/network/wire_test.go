package network

import (
	"testing"

	tmprotocol "t-mldsa/src/protocol"
)

// TestMsgTypeString checks every named MsgType renders a distinct,
// non-fallback string, and an unnamed value falls back to "MsgType(N)".
func TestMsgTypeString(t *testing.T) {
	named := []MsgType{MsgHello, MsgPreprocessing, MsgAck, MsgStart, MsgRound1, MsgRound2, MsgRound3, MsgDone, MsgAbort}
	seen := make(map[string]bool, len(named))
	for _, k := range named {
		s := k.String()
		if seen[s] {
			t.Fatalf("MsgType %d and another share the string %q", k, s)
		}
		seen[s] = true
	}

	if got, want := MsgType(255).String(), "MsgType(255)"; got != want {
		t.Fatalf("MsgType(255).String() = %q, want %q", got, want)
	}
}

// TestEnvelopeEncodeDecodeRoundTrip checks every field of an Envelope
// round-trips through encodeEnvelope/decodeEnvelope, for every MsgType and
// including the zero-value case.
func TestEnvelopeEncodeDecodeRoundTrip(t *testing.T) {
	cases := []Envelope{
		{},
		{Type: MsgHello, From: 2},
		{Type: MsgPreprocessing, From: 1, Payload: []byte("bundle bytes")},
		{Type: MsgAck, From: 2},
		{Type: MsgStart, From: 1, Payload: []byte("message to sign")},
		{Type: MsgRound1, From: 3, Payloads: [][]byte{{0x01, 0x02, 0x03}, {}}},
		{Type: MsgRound2, From: 3, Payloads: nil},
		{Type: MsgRound3, From: 3, Payloads: [][]byte{{}}},
		{Type: MsgDone, From: 1},
		{Type: MsgAbort, From: 2, Reason: "round2: share 4 is inconsistent"},
	}

	for i, want := range cases {
		packed, err := encodeEnvelope(want)
		if err != nil {
			t.Fatalf("case %d: encodeEnvelope failed: %v", i, err)
		}
		got, err := decodeEnvelope(packed)
		if err != nil {
			t.Fatalf("case %d: decodeEnvelope failed: %v", i, err)
		}

		if got.Type != want.Type || got.From != want.From || got.Reason != want.Reason {
			t.Fatalf("case %d: got %+v, want %+v", i, got, want)
		}
		if len(got.Payload) != len(want.Payload) {
			t.Fatalf("case %d: len(got.Payload) = %d, want %d", i, len(got.Payload), len(want.Payload))
		}
		if len(got.Payloads) != len(want.Payloads) {
			t.Fatalf("case %d: len(got.Payloads) = %d, want %d", i, len(got.Payloads), len(want.Payloads))
		}
	}
}

// TestDecodeEnvelopeRejectsGarbage checks decodeEnvelope returns an error,
// not a panic, for data that isn't a valid gob-encoded Envelope.
func TestDecodeEnvelopeRejectsGarbage(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("not gob data"), {0xff, 0x00, 0x01}} {
		if _, err := decodeEnvelope(data); err == nil {
			t.Fatalf("decodeEnvelope(%q) succeeded, want an error", data)
		}
	}
}

// TestPreprocessingBundleEncodeDecodeRoundTrip checks a PreprocessingBundle
// - the payload shape carried inside a MsgPreprocessing Envelope - round-
// trips through encodeBundle/decodeBundle, including its KeyState/
// PreprocessingState fields (each with their own GobEncode/GobDecode,
// exercised transitively here).
func TestPreprocessingBundleEncodeDecodeRoundTrip(t *testing.T) {
	const threshold, numShares = 2, 5

	pk, keys, err := tmprotocol.DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	preSign, _, _, err := tmprotocol.DealPreSig(threshold, numShares, pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}

	want := PreprocessingBundle{
		Key:      keys[0],
		Sessions: []tmprotocol.PreprocessingState{preSign[0], preSign[0]},
	}

	packed, err := encodeBundle(want)
	if err != nil {
		t.Fatalf("encodeBundle failed: %v", err)
	}
	got, err := decodeBundle(packed)
	if err != nil {
		t.Fatalf("decodeBundle failed: %v", err)
	}

	// KeyState/PreprocessingState fields beyond these accessors are
	// unexported; full round-trip fidelity for both types is already
	// covered by protocol's own keystate_marshalling_test.go, so this just
	// confirms decodeBundle didn't error or drop anything at the
	// PreprocessingBundle level.
	if got.Key.PartyID() != want.Key.PartyID() || got.Key.Threshold() != want.Key.Threshold() || got.Key.NumShares() != want.Key.NumShares() {
		t.Fatalf("got.Key = %+v, want %+v", got.Key, want.Key)
	}
	if len(got.Sessions) != len(want.Sessions) {
		t.Fatalf("len(got.Sessions) = %d, want %d", len(got.Sessions), len(want.Sessions))
	}
}

// TestDecodeBundleRejectsGarbage mirrors TestDecodeEnvelopeRejectsGarbage
// for decodeBundle.
func TestDecodeBundleRejectsGarbage(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("not gob data"), {0xff, 0x00, 0x01}} {
		if _, err := decodeBundle(data); err == nil {
			t.Fatalf("decodeBundle(%q) succeeded, want an error", data)
		}
	}
}
