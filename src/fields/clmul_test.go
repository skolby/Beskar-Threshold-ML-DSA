package fields

import (
	"math/rand"
	"testing"
)

// TestClmul64MatchesGeneric cross-checks whatever clmul64 resolves to on
// this platform - clmul64Generic itself off amd64/arm64, or a hardware
// PCLMULQDQ/PMULL implementation when the CPU supports it on amd64/arm64
// (see clmul_amd64.go/clmul_arm64.go) - against clmul64Generic, the ground
// truth every platform's clmul64 must agree with bit-for-bit.
func TestClmul64MatchesGeneric(t *testing.T) {
	edgeCases := []struct{ x, y uint64 }{
		{0, 0},
		{1, 1},
		{^uint64(0), 0},
		{0, ^uint64(0)},
		{^uint64(0), ^uint64(0)},
		{1 << 63, 1 << 63},
		{1, 1 << 63},
		{0x0123456789abcdef, 0xfedcba9876543210},
	}
	for _, c := range edgeCases {
		wantHi, wantLo := clmul64Generic(c.x, c.y)
		gotHi, gotLo := clmul64(c.x, c.y)
		if gotHi != wantHi || gotLo != wantLo {
			t.Fatalf("clmul64(%#x, %#x) = (%#x, %#x), want (%#x, %#x)", c.x, c.y, gotHi, gotLo, wantHi, wantLo)
		}
	}

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		x, y := rng.Uint64(), rng.Uint64()
		wantHi, wantLo := clmul64Generic(x, y)
		gotHi, gotLo := clmul64(x, y)
		if gotHi != wantHi || gotLo != wantLo {
			t.Fatalf("clmul64(%#x, %#x) = (%#x, %#x), want (%#x, %#x)", x, y, gotHi, gotLo, wantHi, wantLo)
		}
	}
}
