package fields

import (
	"crypto/rand"
	"encoding/binary"
)

// Adapt CIRCL code and add appropriate license
type ZQ uint32

const Q uint32 = (1 << 23) - (1 << 13) + 1 // 2^23 - 2^13 + 1
const Qinv uint64 = 4236238847             // = -(q⁻¹) mod 2³²
const rQ uint32 = 4193792                  // 2^32 mod q
const rQSquared uint32 = 2365951           // 2^64 mod q

func (z ZQ) FromUint(x uint32) ZQ {
	if x >= Q {
		panic("value out of range for ZQ")
	}
	return ZQ(x)
}

func (z ZQ) Zero() ZQ {
	return ZQ(0)
}

// PartyPoint returns party partyID's Shamir interpolation point - just
// FromUint(partyID), since ZQ shares are never lifted from another field.
func (z ZQ) PartyPoint(partyID int) ZQ {
	return z.FromUint(uint32(partyID))
}

func (z ZQ) Rand() (ZQ, error) {
	for range maxNumTries {
		r := make([]byte, 4)
		_, err := rand.Read(r)
		if err != nil {
			panic("failed to generate random number")
		}

		r_ := binary.LittleEndian.Uint32(r)
		r_ = r_ & 0x7FFFFF // 2^23-1
		if r_ < Q {
			return ZQ(r_), nil
		}
	}
	//replace with proper random generation
	return ZQ(0), ErrMaxNumTries
}

func (z ZQ) Add(y ZQ) ZQ {
	return ZQ(le2qModQ(uint32(z) + uint32(y)))
}

func (z ZQ) Sub(y ZQ) ZQ {
	return ZQ(le2qModQ(Q + uint32(z) - uint32(y)))
}

func (z ZQ) Mult(y ZQ) ZQ {
	z_ := montProdQ(uint32(z), rQSquared) // convert z to Montgomery form
	y_ := montProdQ(uint32(y), rQSquared) // convert y to Montgomery form
	prod_ := montProdQ(z_, y_)            // multiply in Montgomery form
	return ZQ(montProdQ(prod_, 1))        // convert back from Montgomery form
}

func (z ZQ) Inv() ZQ {
	z_ := montProdQ(uint32(z), rQSquared) // Convert z to Montgomery form
	acc_ := rQ                            // accumulator starts as 1 in Montgomery form
	// Fermat's little theorem in GF(q): z^{-1} = z^(q-2).
	// Fixed-size loop and branchless factor selection keep timing independent of z.
	const e uint32 = Q - 2
	for i := range 32 {
		bit := (e >> (31 - i)) & 1
		acc_ = montProdQ(acc_, acc_)
		factor := bit*z_ + (1-bit)*rQ
		acc_ = montProdQ(acc_, factor)
	}

	return ZQ(montProdQ(acc_, 1)) // Convert back from Montgomery form
}

// takes x and y in Montgomery form, and returns x * y * R^{-1} mod q.
func montProdQ(x, y uint32) uint32 {
	return le2qModQ(montReduceLe2Q(uint64(x) * uint64(y)))
}

/*
Functions below here are adapted from CIRCL code.

Copyright 2020 Cloudflare, Inc.

*/

// Returns a y with y < 2q and y = x mod q.
// Note that in general *not*: ReduceLe2Q(ReduceLe2Q(x)) == x.
func ReduceLe2Q(x uint32) uint32 {
	// Note 2²³ = 2¹³ - 1 mod q. So, writing  x = x₁ 2²³ + x₂ with x₂ < 2²³
	// and x₁ < 2⁹, we have x = y (mod q) where
	// y = x₂ + x₁ 2¹³ - x₁ ≤ 2²³ + 2¹³ < 2q.
	x1 := x >> 23
	x2 := x & 0x7FFFFF // 2²³-1
	return x2 + (x1 << 13) - x1
}

// Returns x mod q.
func modQ(x uint32) uint32 {
	return le2qModQ(ReduceLe2Q(x))
}

// For x R ≤ q 2³², find y ≤ 2q with y = x mod q.
func montReduceLe2Q(x uint64) uint32 {
	// Qinv = 4236238847 = -(q⁻¹) mod 2³²
	m := (x * Qinv) & 0xffffffff
	return uint32((x + m*uint64(Q)) >> 32)
}

// Returns x mod q for 0 ≤ x < 2q.
func le2qModQ(x uint32) uint32 {
	x -= Q
	mask := uint32(int32(x) >> 31) // mask is 2³²-1 if x was neg.; 0 otherwise
	return x + (mask & Q)
}
