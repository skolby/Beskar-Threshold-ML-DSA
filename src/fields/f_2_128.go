// This file implements arithmetic over 𝔽_{2^128}
// 𝔽_2[x]/(x^128 + x^7 + x^2 + x + 1)
package fields

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

type uint128 struct {
	hi uint64
	lo uint64
}

type F2_128 uint128

func (z F2_128) FromUint(x uint32) F2_128 {
	return F2_128{lo: uint64(x)}
}

func (z F2_128) Zero() F2_128 {
	return F2_128{}
}

// PartyPoint returns party partyID's Shamir interpolation point, derived
// indirectly through F2_8's own point rather than FromUint(partyID)
// directly: F2_8 values get lifted into F2_128 elsewhere (ToF2_128, e.g. in
// package protocol's randLinComb) as an additive/multiplicative field
// embedding, which does not commute with FromUint - ToF2_128(F2_8's point
// for a party) is not the same element as F2_128.FromUint(partyID). Using
// that same embedded point here means a lifted F2_8 share still lands on
// the interpolation point Reconstruct expects for that party.
func (z F2_128) PartyPoint(partyID int) F2_128 {
	return F2_8(0).PartyPoint(partyID).ToF2_128()
}

func (z F2_128) Rand() (F2_128, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return F2_128{}, err
	}
	return F2_128{
		hi: binary.BigEndian.Uint64(buf[:8]),
		lo: binary.BigEndian.Uint64(buf[8:]),
	}, nil
}

// Bytes returns the big-endian byte encoding of z, matching Rand's encoding.
func (z F2_128) Bytes() [16]byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], z.hi)
	binary.BigEndian.PutUint64(buf[8:], z.lo)
	return buf
}

// FromBytes decodes b as a big-endian F2_128 element - the inverse of Bytes.
func (z F2_128) FromBytes(b [16]byte) F2_128 {
	return F2_128{
		hi: binary.BigEndian.Uint64(b[:8]),
		lo: binary.BigEndian.Uint64(b[8:]),
	}
}

// GobEncode/GobDecode implement gob.GobEncoder/gob.GobDecoder, built
// directly on Bytes/FromBytes. Needed because F2_128's own fields (hi, lo)
// are unexported: encoding/gob only encodes a struct's exported fields via
// reflection, so without these methods a gob.Encoder would silently drop
// every F2_128 value (encoding it as an empty struct) rather than erroring.
// This lets any exported struct field of type F2_128 - e.g. in package
// network's dealer/preprocessing-distribution messages - round-trip
// through gob transparently, the same way e.g. time.Time does.
func (z F2_128) GobEncode() ([]byte, error) {
	b := z.Bytes()
	return b[:], nil
}

// GobDecode is GobEncode's inverse. Needs a pointer receiver, per
// gob.GobDecoder's contract, so gob can write the decoded value back into
// the caller's variable.
func (z *F2_128) GobDecode(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("fields: F2_128.GobDecode: expected 16 bytes, got %d", len(data))
	}
	var b [16]byte
	copy(b[:], data)
	*z = F2_128{}.FromBytes(b)
	return nil
}

func (x F2_128) Add(y F2_128) F2_128 {
	return F2_128{hi: x.hi ^ y.hi, lo: x.lo ^ y.lo}
}

func (x F2_128) Sub(y F2_128) F2_128 {
	return x.Add(y)
}

func (x F2_128) Mult(y F2_128) F2_128 {
	x0, x1 := uint64(x.lo), uint64(x.hi)
	y0, y1 := uint64(y.lo), uint64(y.hi)

	// Use Karatsuba over GF(2): the cross term is (x0^x1)*(y0^y1) ^ p0 ^ p1.
	// Each 64-bit product is computed as a carryless multiplication.
	p0Hi, p0Lo := clmul64(x0, y0)
	p1Hi, p1Lo := clmul64(x1, y1)
	pmHi, pmLo := clmul64(x0^x1, y0^y1)
	midHi := pmHi ^ p0Hi ^ p1Hi
	midLo := pmLo ^ p0Lo ^ p1Lo

	z0 := p0Lo
	z1 := p0Hi ^ midLo
	z2 := p1Lo ^ midHi
	z3 := p1Hi

	return reduceF2_128(z0, z1, z2, z3)
}

func (x F2_128) Inv() F2_128 {
	if x == (F2_128{}) {
		return F2_128{}
	}

	// In GF(2^128), x^{-1} = x^(2^128-2) for all x. Using the standard
	// square-and-multiply chain keeps the control flow independent of the input.
	acc := x
	for i := 0; i < 126; i++ {
		acc = acc.Mult(acc)
		acc = acc.Mult(x)
	}
	return acc.Mult(acc)
}

// clmul64 itself - the carry-less multiply of two 64-bit halves that Mult's
// Karatsuba combination is built from - is platform-specific: see
// clmul_amd64.go/.s and clmul_arm64.go/.s for the hardware-accelerated
// (PCLMULQDQ/PMULL) versions, clmul_generic.go for the portable fallback
// they both fall back to, and clmul_noasm.go for the platforms that only
// get the fallback.

func reduceF2_128(z0, z1, z2, z3 uint64) F2_128 {
	lo := z0
	hi := z1

	// Reduce the high half modulo x^128 + x^7 + x^2 + x + 1.
	lo ^= z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7)
	hi ^= (z2 >> 57) ^ (z2 >> 62) ^ (z2 >> 63)

	hi ^= z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7)
	carry := (z3 >> 57) ^ (z3 >> 62) ^ (z3 >> 63)
	lo ^= carry

	lo ^= (carry << 1) ^ (carry << 2) ^ (carry << 7)

	return F2_128{hi: hi, lo: lo}
}
