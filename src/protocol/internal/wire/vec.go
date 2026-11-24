package wire

// Fixed-size wire encodings for utils.VecL/VecK over fields.ZQ and
// fields.Z157 - unlike Round1Message/Round2Message/Round3Message's own
// Pack/Unpack functions in ../../marshalling.go, these don't touch any
// protocol-specific type, so they live here rather than there; they don't
// live in utils either; anything that packs a value down to bytes for the
// wire belongs in this package (see wire.go's doc comment).

import (
	"fmt"

	"t-mldsa/src/fields"
	"t-mldsa/src/utils"
)

// zqByteWidth is the number of bytes needed to pack a single fields.ZQ
// coefficient: Q = 2^23 - 2^13 + 1 < 2^23, so every representative fits in
// 3 bytes (24 bits).
const zqByteWidth = 3

// PackVecL packs a utils.VecL[fields.ZQ] (e.g. protocol's Round2State.z,
// [[z]]_q) into a byte slice, encoding each of its L*N coefficients as 3
// little-endian bytes - Q < 2^23, so 3 bytes suffice for every
// representative. UnpackVecL is the inverse.
func PackVecL(v utils.VecL[fields.ZQ]) []byte {
	out := make([]byte, len(v)*zqByteWidth)
	for i, x := range v {
		out[i*zqByteWidth] = byte(x)
		out[i*zqByteWidth+1] = byte(x >> 8)
		out[i*zqByteWidth+2] = byte(x >> 16)
	}
	return out
}

// UnpackVecL is the inverse of PackVecL: it decodes a byte slice produced by
// PackVecL back into a utils.VecL[fields.ZQ]. It returns an error if data
// isn't exactly L*N*3 bytes long. Each decoded coefficient is passed
// through ZQ.FromUint, which enforces the < Q invariant on ZQ's behalf
// (panicking if violated), so that check isn't duplicated here.
func UnpackVecL(data []byte) (utils.VecL[fields.ZQ], error) {
	var v utils.VecL[fields.ZQ]
	wantLen := len(v) * zqByteWidth
	if len(data) != wantLen {
		return utils.VecL[fields.ZQ]{}, fmt.Errorf("wire: expected %d bytes, got %d", wantLen, len(data))
	}

	for i := range v {
		x := uint32(data[i*zqByteWidth]) | uint32(data[i*zqByteWidth+1])<<8 | uint32(data[i*zqByteWidth+2])<<16
		v[i] = fields.ZQ(0).FromUint(x)
	}
	return v, nil
}

// PackVecK mirrors PackVecL for utils.VecK - same 3-little-endian-bytes-per-
// coefficient encoding, just over VecK's K*N coordinates instead of VecL's
// L*N.
func PackVecK(v utils.VecK[fields.ZQ]) []byte {
	out := make([]byte, len(v)*zqByteWidth)
	for i, x := range v {
		out[i*zqByteWidth] = byte(x)
		out[i*zqByteWidth+1] = byte(x >> 8)
		out[i*zqByteWidth+2] = byte(x >> 16)
	}
	return out
}

// UnpackVecK is the inverse of PackVecK.
func UnpackVecK(data []byte) (utils.VecK[fields.ZQ], error) {
	var v utils.VecK[fields.ZQ]
	wantLen := len(v) * zqByteWidth
	if len(data) != wantLen {
		return utils.VecK[fields.ZQ]{}, fmt.Errorf("wire: expected %d bytes, got %d", wantLen, len(data))
	}

	for i := range v {
		x := uint32(data[i*zqByteWidth]) | uint32(data[i*zqByteWidth+1])<<8 | uint32(data[i*zqByteWidth+2])<<16
		v[i] = fields.ZQ(0).FromUint(x)
	}
	return v, nil
}

// PackVecKCompressed mirrors PackVecK for utils.VecKCompressed - same
// 3-little-endian-bytes-per-coefficient encoding, just over
// VecKCompressed's (K*N)/4 coordinates instead of VecK's K*N (a packed w_1
// coordinate is still < Q, same as any other ZQ element, so it needs the
// same 3 bytes - the saving is in there being 4 times fewer of them).
func PackVecKCompressed(v utils.VecKCompressed) []byte {
	out := make([]byte, len(v)*zqByteWidth)
	for i, x := range v {
		out[i*zqByteWidth] = byte(x)
		out[i*zqByteWidth+1] = byte(x >> 8)
		out[i*zqByteWidth+2] = byte(x >> 16)
	}
	return out
}

// UnpackVecKCompressed is the inverse of PackVecKCompressed.
func UnpackVecKCompressed(data []byte) (utils.VecKCompressed, error) {
	var v utils.VecKCompressed
	wantLen := len(v) * zqByteWidth
	if len(data) != wantLen {
		return utils.VecKCompressed{}, fmt.Errorf("wire: expected %d bytes, got %d", wantLen, len(data))
	}

	for i := range v {
		x := uint32(data[i*zqByteWidth]) | uint32(data[i*zqByteWidth+1])<<8 | uint32(data[i*zqByteWidth+2])<<16
		v[i] = fields.ZQ(0).FromUint(x)
	}
	return v, nil
}

// z157ByteWidth is the number of bytes needed to pack a single fields.Z157
// coefficient: every representative is < 157, so a single byte suffices.
const z157ByteWidth = 1

// PackVecLZ157 packs a utils.VecL[fields.Z157] into a byte slice, encoding
// each of its L*N coefficients as a single byte - Z157 < 157 < 2^8, so one
// byte suffices for every representative. UnpackVecLZ157 is the inverse.
func PackVecLZ157(v utils.VecL[fields.Z157]) []byte {
	out := make([]byte, len(v))
	for i, x := range v {
		out[i] = byte(x)
	}
	return out
}

// UnpackVecLZ157 is the inverse of PackVecLZ157. It returns an error if data
// isn't exactly L*N bytes long. Each decoded coefficient is passed through
// Z157.FromUint, which enforces the < 157 invariant on Z157's behalf, so
// that check isn't duplicated here.
func UnpackVecLZ157(data []byte) (utils.VecL[fields.Z157], error) {
	var v utils.VecL[fields.Z157]
	if len(data) != len(v)*z157ByteWidth {
		return utils.VecL[fields.Z157]{}, fmt.Errorf("wire: expected %d bytes, got %d", len(v)*z157ByteWidth, len(data))
	}

	for i := range v {
		v[i] = fields.Z157(0).FromUint(uint32(data[i]))
	}
	return v, nil
}

// PackVecKZ157 mirrors PackVecLZ157 for utils.VecK.
func PackVecKZ157(v utils.VecK[fields.Z157]) []byte {
	out := make([]byte, len(v))
	for i, x := range v {
		out[i] = byte(x)
	}
	return out
}

// UnpackVecKZ157 is the inverse of PackVecKZ157.
func UnpackVecKZ157(data []byte) (utils.VecK[fields.Z157], error) {
	var v utils.VecK[fields.Z157]
	if len(data) != len(v)*z157ByteWidth {
		return utils.VecK[fields.Z157]{}, fmt.Errorf("wire: expected %d bytes, got %d", len(v)*z157ByteWidth, len(data))
	}

	for i := range v {
		v[i] = fields.Z157(0).FromUint(uint32(data[i]))
	}
	return v, nil
}
