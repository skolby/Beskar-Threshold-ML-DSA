package fields

import (
	"crypto/rand"
	"crypto/subtle"
)

type Z157 uint16

const P uint16 = 157
const Pinv uint16 = 75     // -(157^-1) mod 2^8
const r uint16 = 99        // 2^8 mod 157
const rSquared uint16 = 67 // 2^16 mod 157
const Pinv32 uint32 = 3556342347
const r32 uint32 = 93 // 2^32 mod 157

// takes x and y in montgomery form, and returns x * y * r mod n, using Montgomery multiplication
func montProd(x, y uint16) uint16 {
	t := (uint16(x) * uint16(y)) & 0x00FF // x̅ * y̅ mod 2^8
	m := (t * Pinv) & 0x00FF              // t * -(p^{-1}) mod 2^8
	u := (uint16(x)*uint16(y) + m*P) >> 8 // Divide by 2^8
	return le2pModP(uint16(u))
}

// takes x and y mod n, and returns x * y mod n, using Montgomery multiplication
func montMult(x, y uint16) uint16 {
	x_ := montProd(x, rSquared) // convert x to Montgomery form
	y_ := montProd(y, rSquared) // convert y to Montgomery form
	z_ := montProd(x_, y_)      // multiply in Montgomery form
	return montProd(z_, 1)      // convert back from Montgomery form
}

// Returns x mod p for 0 ≤ x < 2p.
func le2pModP(x uint16) uint16 {
	x -= P
	mask := uint16(int16(x) >> 15) // mask is 0xFFFF if x < 0, 0x0000 if x >= 0
	return x + (mask & P)
}

// montReduce32Le2P reduces t modulo 157 with Montgomery radix R=2^32.
// Requires t < 157*R and returns a value in [0, 157).
func montReduce32Le2P(t uint64) uint16 {
	m := uint32(t) * Pinv32
	u := (t + uint64(m)*uint64(P)) >> 32
	return le2pModP(uint16(u))
}

// reduceUint32Mod157 returns x mod 157 in constant time.
func reduceUint32Mod157(x uint32) uint16 {
	return montReduce32Le2P(uint64(x) * uint64(r32))
}

func (z Z157) FromUint(x uint32) Z157 {
	return Z157(reduceUint32Mod157(x))
}

func (z Z157) Zero() Z157 {
	return Z157(0)
}

// PartyPoint returns party partyID's Shamir interpolation point - just
// FromUint(partyID), since Z157 shares are never lifted from another field.
func (z Z157) PartyPoint(partyID int) Z157 {
	return z.FromUint(uint32(partyID))
}

func (z Z157) Rand() (Z157, error) {
	//replace with proper random generation
	for range maxNumTries {
		r := make([]byte, 1)
		rand.Read(r)
		r_ := uint16(r[0])
		if r_ < 157 { // do this comparison in a better way
			return Z157(r_), nil
		}
	}
	return Z157(0), ErrMaxNumTries
}

func (x Z157) Add(y Z157) Z157 {
	// assume that x and y are already reduced mod p
	return Z157(le2pModP(uint16(x) + uint16(y)))
}

func (x Z157) Sub(y Z157) Z157 {
	// assume that x and y are already reduced mod p
	return Z157(le2pModP(uint16(x) + P - uint16(y)))
}

func (x Z157) Mult(y Z157) Z157 {
	return Z157(montMult(uint16(x), uint16(y)))
}

// func (x Z157) Exp(n uint32) Z157 {
// 	x_ := x.montPtrod(Z157(rSquared)) // Convert x to montgomery form
// 	acc x_ := r 						// accumulator starts as 1 in montgomery form
// 	//replace with proper exponentiation
// 	return Z157(0)
// }

func (x Z157) Inv() Z157 { // behaviour for 0 is undef
	x_ := montProd(uint16(x), rSquared) // Convert x to Montgomery form
	acc_ := r                           // accumulator starts as 1 in Montgomery form

	// Fermat's little theorem in GF(p): x^{-1} = x^(p-2), where p-2 = 155 for p=157.
	// Fixed-size loop and branchless factor selection keep timing independent of x.
	const e uint16 = P - 2
	for i := range 8 {
		bit := (e >> (7 - i)) & 1
		acc_ = montProd(acc_, acc_)
		factor := bit*x_ + (1-bit)*r
		acc_ = montProd(acc_, factor)
	}

	return Z157(montProd(acc_, 1)) // Convert back from Montgomery form
}

func Equal(a, b Z157) bool {
	return a == b
}

// ConvertZ157ToZQ embeds x into ZQ, treating its representative in [0, 157)
// as the same non-negative integer mod Q. Since every Z157 value is already
// < Q, this is a direct embedding, not a reduction - it is not the inverse
// of ConvertSmallToZ157, which is lossy (many ZQ values map to the same
// Z157 value).
func ConvertZ157ToZQ(x Z157) ZQ {
	return ZQ(0).FromUint(uint32(x))
}

// Converts x in ZQ to Z157 by first taking the centered representative in (-Q/2, Q/2]
// and then reducing modulo 157. In particular, Q-1 maps to 156.
func ConvertSmallToZ157(x ZQ) Z157 {
	ux := uint32(x)
	// large is 1 iff ux > Q/2, else 0.
	large := uint32(subtle.ConstantTimeLessOrEq(int(Q/2+1), int(ux)))
	centered := int64(ux) - int64(large*Q)

	// Lift centered value to non-negative before reducing mod 157.
	// 26690*157 = 4,190,330 > Q/2 = 4,190,208.
	const lift int64 = 26690 * int64(P)
	return Z157(0).FromUint(uint32(centered + lift))
}
