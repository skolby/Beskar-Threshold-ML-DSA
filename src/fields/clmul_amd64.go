//go:build gc && !purego

package fields

import "golang.org/x/sys/cpu"

// hasCLMUL reports whether the PCLMULQDQ instruction is available on this
// CPU, checked once at package init via golang.org/x/sys/cpu's CPUID-based
// feature detection (https://pkg.go.dev/golang.org/x/sys/cpu).
var hasCLMUL = cpu.X86.HasPCLMULQDQ

// clmul64Hardware computes the 128-bit carry-less (GF(2)) product of x and y
// using the PCLMULQDQ instruction - the same instruction Go's standard
// library uses for hardware-accelerated GHASH (see
// $GOROOT/src/crypto/internal/fips140/aes/gcm/gcm_amd64.s), originally
// introduced for that purpose and described in Shay Gueron and Michael E.
// Kounavis, "Intel® Carry-Less Multiplication Instruction and its Usage for
// Computing the GCM Mode"
// (https://www.intel.com/content/dam/develop/external/us/en/documents/clmul-wp-rev-2-02-2014-04-20.pdf).
// Implemented in clmul_amd64.s.
//
// PCLMULQDQ's native bit convention - integer bit i of an operand is the
// coefficient of x^i - already matches F2_128's own (see the package
// comment in f_2_128.go and Mult's Karatsuba combination), so unlike GHASH
// - which stores bits in the opposite, "reflected" order and must
// bit-reverse its inputs/outputs around every PCLMULQDQ call, see
// reverseBits and the byte-swizzling in Go's own GHASH assembly - this is a
// direct, no-reflection-needed replacement for clmul64Generic.
//
//go:noescape
func clmul64Hardware(x, y uint64) (hi, lo uint64)

func clmul64(x, y uint64) (hi, lo uint64) {
	if hasCLMUL {
		return clmul64Hardware(x, y)
	}
	return clmul64Generic(x, y)
}
