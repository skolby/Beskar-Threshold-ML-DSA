package fields

import "testing"

func f2_128Pow(x F2_128, n int) F2_128 {
	one := F2_128{}.FromUint(1)
	if n == 0 {
		return one
	}
	z := x
	for i := 1; i < n; i++ {
		z = z.Mult(x)
	}
	return z
}

// TestF2_128PartyPointMatchesLiftedF2_8PartyPoint checks that F2_128's
// PartyPoint is exactly its own F2_8 PartyPoint lifted via ToF2_128, for
// every party index a real deployment would use - the property secretsharing
// relies on so that an F2_8 share, lifted into F2_128 (e.g. package
// protocol's randLinComb), lands on the same interpolation point
// Reconstruct(..., F2_128, ...) would use for that party.
func TestF2_128PartyPointMatchesLiftedF2_8PartyPoint(t *testing.T) {
	for partyID := 1; partyID <= 10; partyID++ {
		got := F2_128{}.PartyPoint(partyID)
		want := F2_8(0).PartyPoint(partyID).ToF2_128()
		if got != want {
			t.Fatalf("F2_128{}.PartyPoint(%d) = %+v, want %+v (F2_8's PartyPoint lifted via ToF2_128)", partyID, got, want)
		}
	}
}

// TestF2_128PartyPointIdentityMatchesFromUint checks the one partyID where
// PartyPoint and FromUint are expected to agree: partyID 1, whose point is
// the multiplicative identity in every field. Any field embedding fixes 1
// (that's what makes it a ring homomorphism), so ToF2_128 must map F2_8's
// identity to F2_128's identity, and PartyPoint(1) - defined via that lift -
// must land on FromUint(1) same as a directly-defined field's would.
func TestF2_128PartyPointIdentityMatchesFromUint(t *testing.T) {
	got := F2_128{}.PartyPoint(1)
	want := F2_128{}.FromUint(1)
	if got != want {
		t.Fatalf("F2_128{}.PartyPoint(1) = %+v, want %+v (FromUint(1), the multiplicative identity)", got, want)
	}

	// Same check one level down: F2_8's own PartyPoint(1) must be F2_8's
	// identity too, since PartyPoint(1) is defined as F2_8's PartyPoint(1)
	// lifted, and the lift is required to fix the identity.
	gotF2_8 := F2_8(0).PartyPoint(1)
	wantF2_8 := F2_8(0).FromUint(1)
	if gotF2_8 != wantF2_8 {
		t.Fatalf("F2_8(0).PartyPoint(1) = %+v, want %+v (FromUint(1))", gotF2_8, wantF2_8)
	}
}

// TestF2_128PartyPointDiffersFromFromUint pins down exactly the bug
// PartyPoint fixes: F2_128's interpolation point for a party is NOT simply
// FromUint(partyID) - ToF2_128 is a field embedding, and embeddings don't
// commute with FromUint, so reconstructing a lifted F2_8 share against
// FromUint(partyID) points (as plain Shamir sharing would) uses the wrong
// x-coordinate entirely. Starts at partyID 2: partyID 1's point is the
// multiplicative identity in every field, which every embedding fixes by
// definition, so PartyPoint(1) and FromUint(1) necessarily agree - covered
// separately by TestF2_128PartyPointIdentityMatchesFromUint instead.
func TestF2_128PartyPointDiffersFromFromUint(t *testing.T) {
	for partyID := 2; partyID <= 5; partyID++ {
		partyPoint := F2_128{}.PartyPoint(partyID)
		fromUint := F2_128{}.FromUint(uint32(partyID))
		if partyPoint == fromUint {
			t.Fatalf("F2_128{}.PartyPoint(%d) == FromUint(%d) (%+v) - expected them to differ", partyID, partyID, partyPoint)
		}
	}
}

func TestF2_8ToF2_128SageVectors(t *testing.T) {
	tests := []struct {
		name string
		x    F2_8
		want F2_128
	}{
		{name: "00", x: F2_8(0x00), want: F2_128{hi: 0x0, lo: 0x0}},
		{name: "01", x: F2_8(0x01), want: F2_128{hi: 0x0, lo: 0x1}},
		{name: "02", x: F2_8(0x02), want: F2_128{hi: 0x053d8555a9979a1c, lo: 0xa13fe8ac5560ce0d}},
		{name: "03", x: F2_8(0x03), want: F2_128{hi: 0x053d8555a9979a1c, lo: 0xa13fe8ac5560ce0c}},
		{name: "53", x: F2_8(0x53), want: F2_128{hi: 0xde77167b8539a797, lo: 0x0d972a0b4c6fa967}},
		{name: "57", x: F2_8(0x57), want: F2_128{hi: 0x9283a13819861c13, lo: 0xe1e073c178e70786}},
		{name: "80", x: F2_8(0x80), want: F2_128{hi: 0x0950311a4fb78fe0, lo: 0x7a7a8e94e136f9bc}},
		{name: "83", x: F2_8(0x83), want: F2_128{hi: 0x0c6db44fe62015fc, lo: 0xdb456638b45637b0}},
		{name: "ae", x: F2_8(0xae), want: F2_128{hi: 0x21ac73a21d46a21b, lo: 0xadd6747bcdfc5d4c}},
		{name: "ff", x: F2_8(0xff), want: F2_128{hi: 0xfae6e08c31e89f90, lo: 0x017eb6dcd4f33a26}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.ToF2_128(); got != tt.want {
				t.Fatalf("ToF2_128() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestF2_8ToF2_128RootSatisfiesModulus(t *testing.T) {
	beta := F2_8(0x02).ToF2_128()
	one := F2_128{}.FromUint(1)

	// beta^8 + beta^4 + beta^3 + beta + 1 must be zero.
	v := f2_128Pow(beta, 8)
	v = v.Add(f2_128Pow(beta, 4))
	v = v.Add(f2_128Pow(beta, 3))
	v = v.Add(beta)
	v = v.Add(one)

	if v != (F2_128{}) {
		t.Fatalf("embedded generator does not satisfy u^8 + u^4 + u^3 + u + 1: got %#v", v)
	}
}

func TestF2_8ToF2_128HomomorphismExhaustive(t *testing.T) {
	seen := make(map[F2_128]struct{}, 256)

	for xv := 0; xv < 256; xv++ {
		x := F2_8(uint8(xv))
		xEmb := x.ToF2_128()
		seen[xEmb] = struct{}{}

		for yv := 0; yv < 256; yv++ {
			y := F2_8(uint8(yv))
			yEmb := y.ToF2_128()

			sumF2_8 := x.Add(y)
			wantAddEmb := sumF2_8.ToF2_128()
			gotAddEmb := xEmb.Add(yEmb)
			if gotAddEmb != wantAddEmb {
				t.Fatalf("add homomorphism failed for x=%#x y=%#x: got %#v want %#v", xv, yv, gotAddEmb, wantAddEmb)
			}

			prodF2_8 := x.Mult(y)
			wantMultEmb := prodF2_8.ToF2_128()
			gotMultEmb := xEmb.Mult(yEmb)
			if gotMultEmb != wantMultEmb {
				t.Fatalf("mult homomorphism failed for x=%#x y=%#x: got %#v want %#v", xv, yv, gotMultEmb, wantMultEmb)
			}
		}
	}

	if len(seen) != 256 {
		t.Fatalf("embedding is not injective: got %d distinct images, want 256", len(seen))
	}
}
