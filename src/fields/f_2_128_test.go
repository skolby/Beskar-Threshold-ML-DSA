package fields

import (
	"bytes"
	"encoding/gob"
	"testing"
)

func slowF2_128Mult(x, y F2_128) F2_128 {
	var product F2_128
	addend := x
	for i := 0; i < 128; i++ {
		if (y.lo & 1) == 1 {
			product = product.Add(addend)
		}

		carry := addend.hi >> 63
		addend = F2_128{
			hi: (addend.hi << 1) | (addend.lo >> 63),
			lo: (addend.lo << 1) ^ (0x87 & (0 - carry)),
		}
		y = F2_128{
			hi: y.hi >> 1,
			lo: (y.lo >> 1) | (y.hi << 63),
		}
	}
	return product
}

func TestF2_128FromUintAndZero(t *testing.T) {
	zero := F2_128{}

	if got := zero.FromUint(0); got != zero {
		t.Fatalf("FromUint(0) = %#v, want zero value", got)
	}

	if got := zero.FromUint(42); got != (F2_128{lo: 42}) {
		t.Fatalf("FromUint(42) = %#v, want %#v", got, F2_128{lo: 42})
	}

	if got := zero.Zero(); got != zero {
		t.Fatalf("Zero() = %#v, want zero value", got)
	}
}

// TestF2_128GobEncodeDecodeRoundTrip checks that
// GobDecode(GobEncode(z)) == z directly, without going through a full
// gob.Encoder/Decoder, across a spread of values including the zero value.
func TestF2_128GobEncodeDecodeRoundTrip(t *testing.T) {
	values := []F2_128{
		{},
		{lo: 42},
		{hi: 1},
		{hi: 0xffffffffffffffff, lo: 0xffffffffffffffff},
		F2_128{}.FromUint(12345),
	}

	for _, z := range values {
		packed, err := z.GobEncode()
		if err != nil {
			t.Fatalf("GobEncode(%#v) failed: %v", z, err)
		}
		if len(packed) != 16 {
			t.Fatalf("len(GobEncode(%#v)) = %d, want 16", z, len(packed))
		}

		var got F2_128
		if err := got.GobDecode(packed); err != nil {
			t.Fatalf("GobDecode failed: %v", err)
		}
		if got != z {
			t.Fatalf("GobDecode(GobEncode(%#v)) = %#v, want %#v", z, got, z)
		}
	}
}

// TestF2_128GobDecodeRejectsWrongLength checks GobDecode returns an error -
// not a panic or a silently zero-padded/truncated result - for anything
// other than exactly 16 bytes.
func TestF2_128GobDecodeRejectsWrongLength(t *testing.T) {
	var z F2_128
	for _, data := range [][]byte{nil, make([]byte, 15), make([]byte, 17)} {
		if err := z.GobDecode(data); err == nil {
			t.Fatalf("GobDecode(%d bytes) succeeded, want an error", len(data))
		}
	}
}

// TestF2_128GobRoundTripsThroughAnExportedField checks the actual intended
// use case: F2_128 embedded as an exported field of another struct, encoded
// and decoded via a real gob.Encoder/Decoder pair (not called directly) -
// this only works because F2_128 implements gob.GobEncoder/GobDecoder
// (F2_128's own hi/lo fields are unexported, so plain reflection-based gob
// encoding would otherwise silently drop the value).
func TestF2_128GobRoundTripsThroughAnExportedField(t *testing.T) {
	type wrapper struct {
		X F2_128
		Y []F2_128
	}
	want := wrapper{
		X: F2_128{}.FromUint(999),
		Y: []F2_128{{hi: 1, lo: 2}, {hi: 3, lo: 4}},
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(want); err != nil {
		t.Fatalf("gob Encode failed: %v", err)
	}

	var got wrapper
	if err := gob.NewDecoder(&buf).Decode(&got); err != nil {
		t.Fatalf("gob Decode failed: %v", err)
	}

	if got.X != want.X {
		t.Fatalf("got.X = %#v, want %#v", got.X, want.X)
	}
	if len(got.Y) != len(want.Y) {
		t.Fatalf("len(got.Y) = %d, want %d", len(got.Y), len(want.Y))
	}
	for i := range want.Y {
		if got.Y[i] != want.Y[i] {
			t.Fatalf("got.Y[%d] = %#v, want %#v", i, got.Y[i], want.Y[i])
		}
	}
}

func TestF2_128AddSub(t *testing.T) {
	x := F2_128{lo: 0x1234}
	y := F2_128{lo: 0x5678}
	want := F2_128{lo: 0x1234 ^ 0x5678}

	if got := x.Add(y); got != want {
		t.Fatalf("Add = %#v, want %#v", got, want)
	}
	if got := x.Sub(y); got != want {
		t.Fatalf("Sub = %#v, want %#v", got, want)
	}
}

func TestSlowF2_128MultGroundTruth(t *testing.T) {
	tests := []struct {
		name string
		x    F2_128
		y    F2_128
		want F2_128
	}{
		{
			name: "zero times one",
			x:    F2_128{},
			y:    F2_128{lo: 1},
			want: F2_128{},
		},
		{
			name: "one times one",
			x:    F2_128{lo: 1},
			y:    F2_128{lo: 1},
			want: F2_128{lo: 1},
		},
		{
			name: "x^64 times x^64",
			x:    F2_128{hi: 1},
			y:    F2_128{hi: 1},
			want: F2_128{lo: 0x87},
		},
		{
			name: "x^127 times x",
			x:    F2_128{hi: 1 << 63},
			y:    F2_128{lo: 2},
			want: F2_128{lo: 0x87},
		},
		{
			name: "x^127 plus one times x",
			x:    F2_128{hi: 1 << 63, lo: 1},
			y:    F2_128{lo: 2},
			want: F2_128{lo: 0x85},
		},
		{
			name: "x^64 times x^65",
			x:    F2_128{hi: 1},
			y:    F2_128{hi: 2},
			want: F2_128{lo: 0x10e},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := slowF2_128Mult(tt.x, tt.y); got != tt.want {
				t.Fatalf("slowF2_128Mult = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestF2_128Mult(t *testing.T) {
	tests := []struct {
		name string
		x    F2_128
		y    F2_128
		want F2_128
	}{
		{
			name: "zero times one",
			x:    F2_128{},
			y:    F2_128{lo: 1},
			want: F2_128{},
		},
		{
			name: "one times one",
			x:    F2_128{lo: 1},
			y:    F2_128{lo: 1},
			want: F2_128{lo: 1},
		},
		{
			name: "x^64 times x^64 reduces via modulus",
			x:    F2_128{hi: 1},
			y:    F2_128{hi: 1},
			want: F2_128{lo: 0x87},
		},
		{
			name: "x^127 times x reduces via modulus",
			x:    F2_128{hi: 1 << 63},
			y:    F2_128{lo: 2},
			want: F2_128{lo: 0x87},
		},
		{
			name: "x^127 plus one times x",
			x:    F2_128{hi: 1 << 63, lo: 1},
			y:    F2_128{lo: 2},
			want: F2_128{lo: 0x85},
		},
		{
			name: "x^64 times x^65",
			x:    F2_128{hi: 1},
			y:    F2_128{hi: 2},
			want: F2_128{lo: 0x10e},
		},
		{
			name: "sage case one",
			x:    F2_128{hi: 0x1111111111111111, lo: 0x2222222222222222},
			y:    F2_128{hi: 0x3333333333333333, lo: 0x4444444444444444},
			want: F2_128{hi: 0x8282828282828283, lo: 0x8f8f8f8f8f8f8f08},
		},
		{
			name: "sage case two",
			x:    F2_128{hi: 0xdeadbeefdeadbeef, lo: 0x0123456789abcdef},
			y:    F2_128{hi: 0x0f0e0d0c0b0a0908, lo: 0x0706050403020100},
			want: F2_128{hi: 0xe22f561d984918cc, lo: 0x939b9998c11fca56},
		},
		{
			name: "sage case three",
			x:    F2_128{hi: 0x0123456789abcdef, lo: 0xfedcba9876543210},
			y:    F2_128{hi: 0x0f1e2d3c4b5a6978, lo: 0x8877665544332211},
			want: F2_128{hi: 0x82ee7d300151869d, lo: 0x816ccfac9f6179dd},
		},
		{
			name: "sage case four",
			x:    F2_128{hi: 1, lo: 1},
			y:    F2_128{hi: 1 << 63, lo: 0x0123456789abcdef},
			want: F2_128{hi: 0x8123456789abcdac, lo: 0x8123456789abcdef},
		},
		{
			name: "regression high-overflow reduction",
			x:    F2_128{hi: 0x9b6cffa2ba517936, lo: 0x30b95ff183c471d4},
			y:    F2_128{hi: 0xa8b621587cb3ad0b, lo: 0x3c04951aa42655d9},
			want: F2_128{hi: 0x75de6eaf10e7a2b1, lo: 0x6a2ca7e31116f55e},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.Mult(tt.y); got != tt.want {
				t.Fatalf("Mult = %#v, want %#v", got, tt.want)
			}
		})
	}

}

func TestF2_128Inv(t *testing.T) {
	tests := []struct {
		name string
		x    F2_128
		want F2_128
	}{
		{
			name: "one",
			x:    F2_128{lo: 1},
			want: F2_128{lo: 1},
		},
		{
			name: "x^64 + 1",
			x:    F2_128{hi: 1, lo: 1},
			want: F2_128{hi: 0xfe08629e8e4b766a, lo: 0xfe08629e8e4b7617},
		},
		{
			name: "mixed value",
			x:    F2_128{hi: 0x0123456789abcdef, lo: 0xfedcba9876543210},
			want: F2_128{hi: 0xac20a8a9f088c918, lo: 0xe7a4a93e6b40984a},
		},
		{
			name: "sage case one",
			x:    F2_128{lo: 0x2},
			want: F2_128{hi: 0x8000000000000000, lo: 0x43},
		},
		{
			name: "sage case two",
			x:    F2_128{hi: 0x8000000000000000, lo: 0x1},
			want: F2_128{hi: 0xbaa04291ae2d33f8, lo: 0x31ecbc9dd50214d3},
		},
		{
			name: "sage case three",
			x:    F2_128{hi: 0xabcdef0123456789, lo: 0x13579bdf2468ace0},
			want: F2_128{hi: 0x9d757ca29ad15b19, lo: 0x1bc337f40a5ec6c0},
		},
		{
			name: "sage case four",
			x:    F2_128{hi: 0xffffffffffffffff, lo: 0xffffffffffffffff},
			want: F2_128{hi: 0xfe08629e8e4b766a, lo: 0xfc10c53d1c96eca8},
		},
		{
			name: "sage case five",
			x:    F2_128{hi: 0x0123456789abcdef, lo: 0x1},
			want: F2_128{hi: 0x3027ca40be0a2fef, lo: 0xb8976ae5a2234300},
		},
		{
			name: "zero stays zero",
			x:    F2_128{},
			want: F2_128{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.Inv(); got != tt.want {
				t.Fatalf("Inv = %#v, want %#v", got, tt.want)
			}
		})
	}
}
