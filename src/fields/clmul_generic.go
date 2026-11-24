package fields

// clmul64Generic is the portable, branchless software implementation of the
// carry-less (GF(2)) multiplication of two 64-bit values into a 128-bit
// product. It backs clmul64 on architectures with no hardware carry-less
// multiply (clmul_noasm.go), and is the fallback clmul64 falls back to at
// runtime on amd64/arm64 when the CPU lacks PCLMULQDQ/PMULL (clmul_amd64.go,
// clmul_arm64.go).
func clmul64Generic(x, y uint64) (hi, lo uint64) {
	x0, x1 := uint32(x), uint32(x>>32)
	y0, y1 := uint32(y), uint32(y>>32)

	p0 := ghashMul32(x0, y0)
	p1 := ghashMul32(x1, y1)
	pm := ghashMul32(x0^x1, y0^y1)
	mid := pm ^ p0 ^ p1

	lo = p0 ^ (mid << 32)
	hi = p1 ^ (mid >> 32)
	return hi, lo
}

func ghashMul32(x, y uint32) uint64 {
	// Constant-time carryless multiplication of two 32-bit integers, adapted
	// from the GHASH implementation in the Go standard library.
	var xm, ym [4]uint32
	var z [4]uint64

	for i := range 4 {
		xm[i] = x & (0x11111111 << i)
		ym[i] = y & (0x11111111 << i)
	}

	for i := range 4 {
		z[i] = (uint64(xm[0]) * uint64(ym[i])) ^ (uint64(xm[1]) * uint64(ym[(i+3)%4])) ^ (uint64(xm[2]) * uint64(ym[(i+2)%4])) ^ (uint64(xm[3]) * uint64(ym[(i+1)%4]))
		z[i] &= 0x1111111111111111 << i
	}

	return z[0] | z[1] | z[2] | z[3]
}
