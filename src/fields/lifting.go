package fields

// f2_8EmbeddingBasis contains the images of 1, u, u^2, ..., u^7 under an
// explicit GF(2)-algebra embedding GF(2)[u]/(u^8+u^4+u^3+u+1) -> GF(2^128).
// Values were generated with Sage as powers of a root of u^8+u^4+u^3+u+1
// inside GF(2)[x]/(x^128+x^7+x^2+x+1).
var f2_8EmbeddingBasis = [8]F2_128{
	{hi: 0x0000000000000000, lo: 0x0000000000000001},
	{hi: 0x053d8555a9979a1c, lo: 0xa13fe8ac5560ce0d},
	{hi: 0x4cf4b7439cbfbb84, lo: 0xec7759ca3488aee1},
	{hi: 0x35ad604f7d51d2c6, lo: 0xbfcf02ae363946a8},
	{hi: 0x0dcb364640a222fe, lo: 0x6b8330483c2e9849},
	{hi: 0x549810e11a88dea5, lo: 0x252b49277b1b82b4},
	{hi: 0xd681a5686c0c1f75, lo: 0xc72bf2ef2521ff22},
	{hi: 0x0950311a4fb78fe0, lo: 0x7a7a8e94e136f9bc},
}

// ToF2_128 embeds an F2_8 element into the unique subfield of size 2^8 in
// F2_128 using a fixed GF(2)-linear combination of precomputed basis values.
func (x F2_8) ToF2_128() F2_128 {
	v := uint8(x)
	var z F2_128

	for i := 0; i < 8; i++ {
		bit := uint64((v >> i) & 1)
		mask := uint64(0) - bit
		z.hi ^= f2_8EmbeddingBasis[i].hi & mask
		z.lo ^= f2_8EmbeddingBasis[i].lo & mask
	}

	return z
}
