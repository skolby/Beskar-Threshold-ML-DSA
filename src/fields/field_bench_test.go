package fields

import "testing"

// BenchmarkToF2_128 isolates the cost of lifting a single F2_8 element into
// F2_128 (randLinComb in package protocol does this once per LUT entry).
func BenchmarkToF2_128(b *testing.B) {
	x := F2_8(0x5a)
	var sink F2_128
	for i := 0; i < b.N; i++ {
		sink = x.ToF2_128()
	}
	_ = sink
}

// BenchmarkF2_128Mult isolates the cost of one F2_128 multiplication (the
// Karatsuba/carryless-multiply chain in Mult) - randLinComb does one per LUT
// entry, multiplying the lifted share by its random coefficient.
func BenchmarkF2_128Mult(b *testing.B) {
	x := F2_128{hi: 0x0123456789abcdef, lo: 0xfedcba9876543210}
	y := F2_128{hi: 0x1111111111111111, lo: 0x2222222222222222}
	var sink F2_128
	for i := 0; i < b.N; i++ {
		sink = x.Mult(y)
	}
	_ = sink
}

// BenchmarkF2_128Add is a cheap baseline (two XORs) for comparison against
// Mult and ToF2_128.
func BenchmarkF2_128Add(b *testing.B) {
	x := F2_128{hi: 0x0123456789abcdef, lo: 0xfedcba9876543210}
	y := F2_128{hi: 0x1111111111111111, lo: 0x2222222222222222}
	var sink F2_128
	for i := 0; i < b.N; i++ {
		sink = x.Add(y)
	}
	_ = sink
}

// BenchmarkF2_8Mult is a baseline for comparison: how cheap the underlying
// F2_8 multiply (shares live in F2_8 before randLinComb lifts them) is next
// to F2_128's.
func BenchmarkF2_8Mult(b *testing.B) {
	x := F2_8(0x5a)
	y := F2_8(0xa5)
	var sink F2_8
	for i := 0; i < b.N; i++ {
		sink = x.Mult(y)
	}
	_ = sink
}
