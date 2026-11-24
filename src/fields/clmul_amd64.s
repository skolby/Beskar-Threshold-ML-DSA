// Hardware carry-less multiply for amd64 - see clmul_amd64.go for the
// Go-side dispatch and references (Intel's PCLMULQDQ white paper, and
// Go's own PCLMULQDQ-based GHASH in
// crypto/internal/fips140/aes/gcm/gcm_amd64.s, which this mirrors the
// bare-multiply core of).
#include "textflag.h"

// func clmul64Hardware(x, y uint64) (hi, lo uint64)
TEXT ·clmul64Hardware(SB), NOSPLIT, $0-32
	MOVQ x+0(FP), AX
	MOVQ y+8(FP), CX
	MOVQ AX, X0
	MOVQ CX, X1

	// X0 = CLMUL(X0[63:0], X1[63:0]), the 128-bit carry-less product of the
	// two low quadwords ($0x00 selects the low half of both operands).
	PCLMULQDQ $0x00, X1, X0
	MOVQ      X0, lo+24(FP)
	PSHUFD    $0xEE, X0, X0 // X0's low 64 bits <- X0's high 64 bits
	MOVQ      X0, hi+16(FP)
	RET
