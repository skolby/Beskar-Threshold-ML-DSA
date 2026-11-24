package wire

import (
	"testing"

	"t-mldsa/src/fields"
)

// TestPackUnpackF2_128SliceRoundTrip checks that UnpackF2_128Slice recovers
// exactly the slice PackF2_128Slice packed, with no bytes left over.
func TestPackUnpackF2_128SliceRoundTrip(t *testing.T) {
	xs := make([]fields.F2_128, 5)
	for i := range xs {
		xs[i] = fields.F2_128{}.FromBytes([16]byte{byte(i), byte(i + 1)})
	}

	packed := PackF2_128Slice(nil, xs)
	got, rest, err := UnpackF2_128Slice(packed)
	if err != nil {
		t.Fatalf("UnpackF2_128Slice failed: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("UnpackF2_128Slice left %d trailing bytes, want 0", len(rest))
	}
	if len(got) != len(xs) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(xs))
	}
	for i := range xs {
		if got[i] != xs[i] {
			t.Fatalf("got[%d] = %+v, want %+v", i, got[i], xs[i])
		}
	}
}

// TestPackUnpackF2_128SliceEmpty checks the zero-length slice round-trips
// too, encoding to just the 4-byte length prefix.
func TestPackUnpackF2_128SliceEmpty(t *testing.T) {
	packed := PackF2_128Slice(nil, nil)
	if len(packed) != lengthPrefixWidth {
		t.Fatalf("len(PackF2_128Slice(nil, nil)) = %d, want %d", len(packed), lengthPrefixWidth)
	}

	got, rest, err := UnpackF2_128Slice(packed)
	if err != nil {
		t.Fatalf("UnpackF2_128Slice failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
	if len(rest) != 0 {
		t.Fatalf("len(rest) = %d, want 0", len(rest))
	}
}

// TestPackF2_128SliceThenSomethingElseLeavesTheRest checks that
// UnpackF2_128Slice only consumes its own encoding, leaving whatever
// follows in rest untouched - the basis for chaining several
// Pack/Unpack calls to build up one message, as marshalling.go does.
func TestPackF2_128SliceThenSomethingElseLeavesTheRest(t *testing.T) {
	xs := []fields.F2_128{fields.F2_128{}.FromBytes([16]byte{1})}
	trailer := []byte{0xaa, 0xbb, 0xcc}

	packed := PackF2_128Slice(nil, xs)
	packed = append(packed, trailer...)

	got, rest, err := UnpackF2_128Slice(packed)
	if err != nil {
		t.Fatalf("UnpackF2_128Slice failed: %v", err)
	}
	if len(got) != 1 || got[0] != xs[0] {
		t.Fatalf("got = %+v, want %+v", got, xs)
	}
	if string(rest) != string(trailer) {
		t.Fatalf("rest = %v, want %v", rest, trailer)
	}
}

// TestUnpackF2_128SliceRejectsTruncatedData checks that a length prefix
// promising more elements than the data actually holds is rejected, rather
// than silently reading past the promised elements or panicking.
func TestUnpackF2_128SliceRejectsTruncatedData(t *testing.T) {
	xs := make([]fields.F2_128, 3)
	packed := PackF2_128Slice(nil, xs)

	if _, _, err := UnpackF2_128Slice(packed[:len(packed)-1]); err == nil {
		t.Fatalf("UnpackF2_128Slice(truncated data) succeeded, want an error")
	}
	if _, _, err := UnpackF2_128Slice(nil); err == nil {
		t.Fatalf("UnpackF2_128Slice(nil) succeeded, want an error")
	}
}

// TestPackUnpackBytesRoundTrip checks that UnpackBytes recovers exactly the
// slice PackBytes packed, with no bytes left over.
func TestPackUnpackBytesRoundTrip(t *testing.T) {
	b := []byte("some ciphertext, of arbitrary length")

	packed := PackBytes(nil, b)
	got, rest, err := UnpackBytes(packed)
	if err != nil {
		t.Fatalf("UnpackBytes failed: %v", err)
	}
	if string(got) != string(b) {
		t.Fatalf("got = %q, want %q", got, b)
	}
	if len(rest) != 0 {
		t.Fatalf("len(rest) = %d, want 0", len(rest))
	}
}

// TestPackUnpackBytesEmpty checks the zero-length byte slice round-trips
// too.
func TestPackUnpackBytesEmpty(t *testing.T) {
	packed := PackBytes(nil, nil)
	if len(packed) != lengthPrefixWidth {
		t.Fatalf("len(PackBytes(nil, nil)) = %d, want %d", len(packed), lengthPrefixWidth)
	}

	got, rest, err := UnpackBytes(packed)
	if err != nil {
		t.Fatalf("UnpackBytes failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
	if len(rest) != 0 {
		t.Fatalf("len(rest) = %d, want 0", len(rest))
	}
}

// TestUnpackBytesRejectsTruncatedData mirrors
// TestUnpackF2_128SliceRejectsTruncatedData for UnpackBytes.
func TestUnpackBytesRejectsTruncatedData(t *testing.T) {
	packed := PackBytes(nil, []byte("hello"))

	if _, _, err := UnpackBytes(packed[:len(packed)-1]); err == nil {
		t.Fatalf("UnpackBytes(truncated data) succeeded, want an error")
	}
	if _, _, err := UnpackBytes(nil); err == nil {
		t.Fatalf("UnpackBytes(nil) succeeded, want an error")
	}
}

// TestPackTwoF2_128SlicesThenBytesChains checks the exact chaining pattern
// PackRound3Message uses: two PackF2_128Slice calls followed by a PackBytes
// call, each appending to the previous result, decode back to the right
// three pieces in order.
func TestPackTwoF2_128SlicesThenBytesChains(t *testing.T) {
	a := []fields.F2_128{fields.F2_128{}.FromBytes([16]byte{1}), fields.F2_128{}.FromBytes([16]byte{2})}
	b := []fields.F2_128{fields.F2_128{}.FromBytes([16]byte{3})}
	c := []byte{0x01, 0x02, 0x03, 0x04}

	var out []byte
	out = PackF2_128Slice(out, a)
	out = PackF2_128Slice(out, b)
	out = PackBytes(out, c)

	gotA, rest, err := UnpackF2_128Slice(out)
	if err != nil {
		t.Fatalf("unpacking a: %v", err)
	}
	gotB, rest, err := UnpackF2_128Slice(rest)
	if err != nil {
		t.Fatalf("unpacking b: %v", err)
	}
	gotC, rest, err := UnpackBytes(rest)
	if err != nil {
		t.Fatalf("unpacking c: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("len(rest) = %d, want 0", len(rest))
	}

	if len(gotA) != len(a) || gotA[0] != a[0] || gotA[1] != a[1] {
		t.Fatalf("gotA = %+v, want %+v", gotA, a)
	}
	if len(gotB) != len(b) || gotB[0] != b[0] {
		t.Fatalf("gotB = %+v, want %+v", gotB, b)
	}
	if string(gotC) != string(c) {
		t.Fatalf("gotC = %v, want %v", gotC, c)
	}
}
