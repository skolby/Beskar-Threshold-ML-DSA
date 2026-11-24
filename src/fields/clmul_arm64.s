// Hardware carry-less multiply for arm64 - see clmul_arm64.go for the
// Go-side dispatch and references (the Arm Architecture Reference Manual's
// PMULL, and Go's own PMULL-based GHASH in
// crypto/internal/fips140/aes/gcm/gcm_arm64.s, which this mirrors the
// bare-multiply core of).
#include "textflag.h"

// func clmul64Hardware(x, y uint64) (hi, lo uint64)
TEXT ·clmul64Hardware(SB), NOSPLIT, $0-32
	MOVD x+0(FP), R0
	MOVD y+8(FP), R1
	VMOV R0, V0.D[0]
	VMOV R1, V1.D[0]

	// V2 = CLMUL(V0.D[0], V1.D[0]), the 128-bit carry-less product of the
	// two low doublewords (.D1 selects the low lane of each source, .Q1 the
	// full 128-bit destination).
	VPMULL V0.D1, V1.D1, V2.Q1
	VMOV   V2.D[0], R2
	VMOV   V2.D[1], R3
	MOVD   R2, lo+24(FP)
	MOVD   R3, hi+16(FP)
	RET
