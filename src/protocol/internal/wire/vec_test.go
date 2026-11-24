package wire

import (
	"testing"

	"t-mldsa/src/fields"
	"t-mldsa/src/utils"
)

// TestPackVecLLength checks PackVecL always produces exactly 3 bytes per
// coefficient - L*N*3 total - regardless of the coefficients' values.
func TestPackVecLLength(t *testing.T) {
	var v utils.VecL[fields.ZQ]
	got := len(PackVecL(v))
	want := utils.L * utils.N * 3
	if got != want {
		t.Fatalf("len(PackVecL(v)) = %d, want %d", got, want)
	}
}

// TestPackVecLEncodesLittleEndian pins down the exact byte layout: each
// coefficient is encoded as 3 little-endian bytes, in order.
func TestPackVecLEncodesLittleEndian(t *testing.T) {
	var v utils.VecL[fields.ZQ]
	v[0] = fields.ZQ(0).FromUint(0x030201)
	v[1] = fields.ZQ(0).FromUint(0x000001)

	got := PackVecL(v)
	want := []byte{0x01, 0x02, 0x03, 0x01, 0x00, 0x00}
	for i, b := range want {
		if got[i] != b {
			t.Fatalf("PackVecL(v)[%d] = 0x%02x, want 0x%02x", i, got[i], b)
		}
	}
}

// TestPackUnpackVecLRoundTrip checks that UnpackVecL(PackVecL(v)) == v across
// a spread of coefficient values, including the extremes 0 and Q-1.
func TestPackUnpackVecLRoundTrip(t *testing.T) {
	var v utils.VecL[fields.ZQ]
	for j := range v {
		switch j % 3 {
		case 0:
			v[j] = fields.ZQ(0).FromUint(0)
		case 1:
			v[j] = fields.ZQ(0).FromUint(fields.Q - 1)
		case 2:
			v[j] = fields.ZQ(0).FromUint(uint32(j) % fields.Q)
		}
	}

	packed := PackVecL(v)
	got, err := UnpackVecL(packed)
	if err != nil {
		t.Fatalf("UnpackVecL failed: %v", err)
	}
	if got != v {
		t.Fatalf("UnpackVecL(PackVecL(v)) != v")
	}
}

// TestPackUnpackVecLZeroVector checks the all-zero vector round-trips too,
// as a minimal sanity check independent of the mixed-value round trip above.
func TestPackUnpackVecLZeroVector(t *testing.T) {
	var v utils.VecL[fields.ZQ]

	got, err := UnpackVecL(PackVecL(v))
	if err != nil {
		t.Fatalf("UnpackVecL failed: %v", err)
	}
	if got != v {
		t.Fatalf("UnpackVecL(PackVecL(zero vector)) != zero vector")
	}
}

// TestUnpackVecLRejectsWrongLength checks UnpackVecL returns an error - not
// a panic or a silently truncated/zero-padded result - when given a byte
// slice that isn't exactly L*N*3 bytes long.
func TestUnpackVecLRejectsWrongLength(t *testing.T) {
	want := utils.L * utils.N * 3

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte short", make([]byte, want-1)},
		{"one byte long", make([]byte, want+1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnpackVecL(tc.data); err == nil {
				t.Fatalf("UnpackVecL(%d bytes) succeeded, want an error", len(tc.data))
			}
		})
	}
}

// TestUnpackVecLRejectsOutOfRangeCoefficient checks that a 3-byte group
// encoding a value >= Q - unreachable via PackVecL, since ZQ values are
// always < Q, but reachable from an arbitrary/corrupted byte slice - is
// rejected rather than silently accepted. ZQ.FromUint panics on an
// out-of-range value, so UnpackVecL is expected to panic here too.
func TestUnpackVecLRejectsOutOfRangeCoefficient(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("UnpackVecL(coefficient >= Q) did not panic")
		}
	}()

	data := make([]byte, utils.L*utils.N*3)
	// First coefficient's 3 bytes decode to Q, which is out of range - Q's
	// low 24 bits, little-endian. Routed through a variable so the byte()
	// conversions truncate at runtime instead of failing to compile as
	// non-representable constant conversions.
	q := fields.Q
	data[0] = byte(q)
	data[1] = byte(q >> 8)
	data[2] = byte(q >> 16)

	_, _ = UnpackVecL(data)
}

// TestPackUnpackVecKRoundTrip mirrors TestPackUnpackVecLRoundTrip for VecK -
// same 3-byte-per-coefficient encoding, just over K*N coordinates.
func TestPackUnpackVecKRoundTrip(t *testing.T) {
	var v utils.VecK[fields.ZQ]
	for j := range v {
		switch j % 3 {
		case 0:
			v[j] = fields.ZQ(0).FromUint(0)
		case 1:
			v[j] = fields.ZQ(0).FromUint(fields.Q - 1)
		case 2:
			v[j] = fields.ZQ(0).FromUint(uint32(j) % fields.Q)
		}
	}

	packed := PackVecK(v)
	if len(packed) != utils.K*utils.N*3 {
		t.Fatalf("len(PackVecK(v)) = %d, want %d", len(packed), utils.K*utils.N*3)
	}
	got, err := UnpackVecK(packed)
	if err != nil {
		t.Fatalf("UnpackVecK failed: %v", err)
	}
	if got != v {
		t.Fatalf("UnpackVecK(PackVecK(v)) != v")
	}
}

// TestUnpackVecKRejectsWrongLength mirrors TestUnpackVecLRejectsWrongLength
// for VecK.
func TestUnpackVecKRejectsWrongLength(t *testing.T) {
	want := utils.K * utils.N * 3

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte short", make([]byte, want-1)},
		{"one byte long", make([]byte, want+1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnpackVecK(tc.data); err == nil {
				t.Fatalf("UnpackVecK(%d bytes) succeeded, want an error", len(tc.data))
			}
		})
	}
}

// TestPackUnpackVecKCompressedRoundTrip mirrors TestPackUnpackVecKRoundTrip
// for VecKCompressed - same 3-byte-per-coefficient encoding, just over
// (K*N)/4 coordinates.
func TestPackUnpackVecKCompressedRoundTrip(t *testing.T) {
	var v utils.VecKCompressed
	for j := range v {
		switch j % 3 {
		case 0:
			v[j] = fields.ZQ(0).FromUint(0)
		case 1:
			v[j] = fields.ZQ(0).FromUint(fields.Q - 1)
		case 2:
			v[j] = fields.ZQ(0).FromUint(uint32(j) % fields.Q)
		}
	}

	packed := PackVecKCompressed(v)
	wantLen := utils.K * utils.N / 4 * 3
	if len(packed) != wantLen {
		t.Fatalf("len(PackVecKCompressed(v)) = %d, want %d", len(packed), wantLen)
	}
	got, err := UnpackVecKCompressed(packed)
	if err != nil {
		t.Fatalf("UnpackVecKCompressed failed: %v", err)
	}
	if got != v {
		t.Fatalf("UnpackVecKCompressed(PackVecKCompressed(v)) != v")
	}
}

// TestUnpackVecKCompressedRejectsWrongLength mirrors
// TestUnpackVecKRejectsWrongLength for VecKCompressed.
func TestUnpackVecKCompressedRejectsWrongLength(t *testing.T) {
	want := utils.K * utils.N / 4 * 3

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte short", make([]byte, want-1)},
		{"one byte long", make([]byte, want+1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnpackVecKCompressed(tc.data); err == nil {
				t.Fatalf("UnpackVecKCompressed(%d bytes) succeeded, want an error", len(tc.data))
			}
		})
	}
}

// TestPackUnpackVecLZ157RoundTrip checks UnpackVecLZ157(PackVecLZ157(v)) == v
// across the whole Z157 range, and that the encoding is exactly one byte
// per coefficient.
func TestPackUnpackVecLZ157RoundTrip(t *testing.T) {
	var v utils.VecL[fields.Z157]
	for j := range v {
		v[j] = fields.Z157(0).FromUint(uint32(j % utils.TWidth))
	}

	packed := PackVecLZ157(v)
	if len(packed) != utils.L*utils.N {
		t.Fatalf("len(PackVecLZ157(v)) = %d, want %d", len(packed), utils.L*utils.N)
	}
	got, err := UnpackVecLZ157(packed)
	if err != nil {
		t.Fatalf("UnpackVecLZ157 failed: %v", err)
	}
	if got != v {
		t.Fatalf("UnpackVecLZ157(PackVecLZ157(v)) != v")
	}
}

// TestUnpackVecLZ157RejectsWrongLength mirrors TestUnpackVecLRejectsWrongLength
// for the one-byte-per-coefficient Z157 encoding.
func TestUnpackVecLZ157RejectsWrongLength(t *testing.T) {
	want := utils.L * utils.N

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"one byte short", make([]byte, want-1)},
		{"one byte long", make([]byte, want+1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UnpackVecLZ157(tc.data); err == nil {
				t.Fatalf("UnpackVecLZ157(%d bytes) succeeded, want an error", len(tc.data))
			}
		})
	}
}

// TestPackUnpackVecKZ157RoundTrip mirrors TestPackUnpackVecLZ157RoundTrip for
// VecK.
func TestPackUnpackVecKZ157RoundTrip(t *testing.T) {
	var v utils.VecK[fields.Z157]
	for j := range v {
		v[j] = fields.Z157(0).FromUint(uint32(j % utils.TWidth))
	}

	packed := PackVecKZ157(v)
	if len(packed) != utils.K*utils.N {
		t.Fatalf("len(PackVecKZ157(v)) = %d, want %d", len(packed), utils.K*utils.N)
	}
	got, err := UnpackVecKZ157(packed)
	if err != nil {
		t.Fatalf("UnpackVecKZ157 failed: %v", err)
	}
	if got != v {
		t.Fatalf("UnpackVecKZ157(PackVecKZ157(v)) != v")
	}
}
