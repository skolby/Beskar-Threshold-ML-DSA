// This file implements arithmetic over 𝔽_{2^8}
// 𝔽_2[x]/(x^8 + x^4 + x^3 + x + 1)

package fields

import "crypto/rand"

type F2_8 uint8

// func requireFieldElement[T FieldElement[T]](_ T) {}

// var _ = requireFieldElement[F2_8]

func (z F2_8) FromUint(x uint32) F2_8 {
	return F2_8(uint8(x))
}

func (z F2_8) Zero() F2_8 {
	return F2_8(0)
}

// PartyPoint returns party partyID's Shamir interpolation point -
// FromUint(partyID). F2_128's PartyPoint is derived from this one (via
// ToF2_128), so any change here must stay in sync with that derivation.
func (z F2_8) PartyPoint(partyID int) F2_8 {
	return z.FromUint(uint32(partyID))
}

func (z F2_8) Rand() (F2_8, error) {
	var buf [1]byte
	// cannot return error
	rand.Read(buf[:])
	return F2_8(buf[0]), nil
}

func (x F2_8) Add(y F2_8) F2_8 {
	return x ^ y
}

func (x F2_8) Sub(y F2_8) F2_8 {
	return x ^ y
}

func (x F2_8) Mult(y F2_8) F2_8 {
	var product uint8
	a := uint8(x)
	b := uint8(y)

	// Process two bits of the multiplier per iteration so the loop runs in
	// four steps instead of eight while remaining branchless.
	for i := 0; i < 4; i++ {
		bits := b & 0x03
		mask0 := uint8(0 - (bits & 0x01))
		mask1 := uint8(0 - ((bits >> 1) & 0x01))

		product ^= a & mask0
		product ^= reduceShift1(a) & mask1

		a = reduceShift2(a)
		b >>= 2
	}
	return F2_8(product)
}

func reduceShift1(v uint8) uint8 {
	carry := (v >> 7) & 1
	return (v << 1) ^ (0x1B & uint8(0-carry))
}

func reduceShift2(v uint8) uint8 {
	return reduceShift1(reduceShift1(v))
}

func (x F2_8) Inv() F2_8 {
	// Fixed addition chain for x^254 in GF(2^8); x=0 naturally maps to 0.
	t2 := x.Mult(x)
	t4 := t2.Mult(t2)
	t8 := t4.Mult(t4)
	t16 := t8.Mult(t8)
	t32 := t16.Mult(t16)
	t64 := t32.Mult(t32)
	t128 := t64.Mult(t64)
	return t128.Mult(t64).Mult(t32).Mult(t16).Mult(t8).Mult(t4).Mult(t2)
}
