// Package wire holds small, struct-agnostic byte-encoding primitives used
// to build the round message Pack/Unpack functions in package protocol
// (see marshalling.go there). It exists as its own internal package,
// rather than living directly in protocol or in utils, because it isn't
// about protocol's specific message types (those keep their fields
// unexported, so encoding them has to happen in package protocol itself)
// and isn't a general vector/field codec either (that's utils'
// PackVecK/PackVecLZ157/etc.) - it's just the variable-length,
// length-prefixed framing those message encodings are built out of.
package wire

import (
	"encoding/binary"
	"fmt"

	"t-mldsa/src/fields"
)

// F2_128ByteWidth is the number of bytes fields.F2_128's own Bytes/FromBytes
// encoding uses.
const F2_128ByteWidth = 16

// lengthPrefixWidth is the number of bytes used to encode a length prefix.
const lengthPrefixWidth = 4

// PackF2_128Slice appends a []fields.F2_128 to out, as a 4-byte
// little-endian length prefix followed by that many 16-byte F2_128
// encodings, and returns the extended slice. UnpackF2_128Slice is the
// inverse.
func PackF2_128Slice(out []byte, xs []fields.F2_128) []byte {
	out = binary.LittleEndian.AppendUint32(out, uint32(len(xs)))
	for _, x := range xs {
		b := x.Bytes()
		out = append(out, b[:]...)
	}
	return out
}

// UnpackF2_128Slice decodes a []fields.F2_128 previously packed by
// PackF2_128Slice off the front of data, returning the slice and however
// much of data is left unconsumed.
func UnpackF2_128Slice(data []byte) (xs []fields.F2_128, rest []byte, err error) {
	if len(data) < lengthPrefixWidth {
		return nil, nil, fmt.Errorf("wire: too short to hold a length prefix")
	}
	n := int(binary.LittleEndian.Uint32(data))
	data = data[lengthPrefixWidth:]

	wantLen := n * F2_128ByteWidth
	if len(data) < wantLen {
		return nil, nil, fmt.Errorf("wire: expected at least %d bytes for %d F2_128 elements, got %d", wantLen, n, len(data))
	}

	xs = make([]fields.F2_128, n)
	for i := range xs {
		var b [F2_128ByteWidth]byte
		copy(b[:], data[i*F2_128ByteWidth:(i+1)*F2_128ByteWidth])
		xs[i] = fields.F2_128{}.FromBytes(b)
	}
	return xs, data[wantLen:], nil
}

// PackBytes appends a []byte to out, as a 4-byte little-endian length
// prefix followed by the bytes themselves, and returns the extended slice.
// UnpackBytes is the inverse.
func PackBytes(out []byte, b []byte) []byte {
	out = binary.LittleEndian.AppendUint32(out, uint32(len(b)))
	out = append(out, b...)
	return out
}

// UnpackBytes decodes a []byte previously packed by PackBytes off the front
// of data, returning the bytes and however much of data is left unconsumed.
func UnpackBytes(data []byte) (b []byte, rest []byte, err error) {
	if len(data) < lengthPrefixWidth {
		return nil, nil, fmt.Errorf("wire: too short to hold a length prefix")
	}
	n := int(binary.LittleEndian.Uint32(data))
	data = data[lengthPrefixWidth:]
	if len(data) < n {
		return nil, nil, fmt.Errorf("wire: expected at least %d bytes, got %d", n, len(data))
	}

	b = make([]byte, n)
	copy(b, data[:n])
	return b, data[n:], nil
}
