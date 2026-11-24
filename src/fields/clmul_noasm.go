//go:build (!amd64 && !arm64) || !gc || purego

package fields

// clmul64 falls back to the portable software implementation on
// architectures (or builds) with no hardware carry-less multiply here - see
// clmul_amd64.go/clmul_arm64.go for the accelerated ones.
func clmul64(x, y uint64) (hi, lo uint64) {
	return clmul64Generic(x, y)
}
