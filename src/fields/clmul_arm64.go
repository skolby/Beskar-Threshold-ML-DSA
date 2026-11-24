//go:build gc && !purego

package fields

import "golang.org/x/sys/cpu"

// hasCLMUL reports whether the ARMv8 Cryptography Extension's PMULL
// instruction is available on this CPU, checked once at package init via
// golang.org/x/sys/cpu's feature detection
// (https://pkg.go.dev/golang.org/x/sys/cpu).
var hasCLMUL = cpu.ARM64.HasPMULL

// clmul64Hardware computes the 128-bit carry-less (GF(2)) product of x and y
// using the PMULL instruction - the same instruction Go's standard library
// uses for hardware-accelerated GHASH (see
// $GOROOT/src/crypto/internal/fips140/aes/gcm/gcm_arm64.s), specified in the
// Arm Architecture Reference Manual for A-profile architecture (ARM DDI
// 0487) under PMULL/PMULL2 (vector, polynomial multiply of two 64-bit
// values into a 128-bit result). Implemented in clmul_arm64.s.
//
// As on amd64 (see clmul_amd64.go), PMULL's native bit convention already
// matches F2_128's, so this is a direct replacement for clmul64Generic with
// no bit-reversal step.
//
//go:noescape
func clmul64Hardware(x, y uint64) (hi, lo uint64)

func clmul64(x, y uint64) (hi, lo uint64) {
	if hasCLMUL {
		return clmul64Hardware(x, y)
	}
	return clmul64Generic(x, y)
}
