package fields

import "testing"

func TestF28ImplementsFieldElementBasics(t *testing.T) {
	var zero F2_8

	if got := zero.FromUint(0); got != zero {
		t.Fatalf("FromUint(0) = %#v, want zero", got)
	}

	if got := zero.FromUint(0x123); got != F2_8(0x23) {
		t.Fatalf("FromUint(0x123) = %#v, want %#v", got, F2_8(0x23))
	}

	if got := zero.Zero(); got != zero {
		t.Fatalf("Zero() = %#v, want zero", got)
	}
}

func TestF28Arithmetic(t *testing.T) {
	x := F2_8(0x57)
	y := F2_8(0x83)

	if got := x.Add(y); got != F2_8(0xD4) {
		t.Fatalf("Add = %#v, want %#v", got, F2_8(0xD4))
	}

	if got := x.Sub(y); got != F2_8(0xD4) {
		t.Fatalf("Sub = %#v, want %#v", got, F2_8(0xD4))
	}

	if got := x.Mult(y); got != F2_8(0xC1) {
		t.Fatalf("Mult = %#v, want %#v", got, F2_8(0xC1))
	}

	inv := F2_8(0x53).Inv()
	if got := inv.Mult(F2_8(0x53)); got != F2_8(1) {
		t.Fatalf("Inv(x) * x = %#v, want 1", got)
	}
}

func TestF28MultSageVectors(t *testing.T) {
	tests := []struct {
		name string
		x    F2_8
		y    F2_8
		want F2_8
	}{
		{name: "sage case one", x: F2_8(0x57), y: F2_8(0x83), want: F2_8(0xC1)},
		{name: "sage case two", x: F2_8(0x12), y: F2_8(0x34), want: F2_8(0x05)},
		{name: "sage case three", x: F2_8(0xAA), y: F2_8(0x55), want: F2_8(0x59)},
		{name: "sage case four", x: F2_8(0xC3), y: F2_8(0x0F), want: F2_8(0x3D)},
		{name: "sage case five", x: F2_8(0x01), y: F2_8(0x02), want: F2_8(0x02)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.Mult(tt.y); got != tt.want {
				t.Fatalf("Mult = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestF28InvSageVectors(t *testing.T) {
	tests := []struct {
		name string
		x    F2_8
		want F2_8
	}{
		{name: "one", x: F2_8(0x01), want: F2_8(0x01)},
		{name: "two", x: F2_8(0x02), want: F2_8(0x8D)},
		{name: "five-a", x: F2_8(0x5A), want: F2_8(0x22)},
		{name: "fifty-three", x: F2_8(0x53), want: F2_8(0xCA)},
		{name: "c3", x: F2_8(0xC3), want: F2_8(0xA3)},
		{name: "ff", x: F2_8(0xFF), want: F2_8(0x1C)},
		{name: "80", x: F2_8(0x80), want: F2_8(0x83)},
		{name: "7e", x: F2_8(0x7E), want: F2_8(0x81)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.Inv(); got != tt.want {
				t.Fatalf("Inv = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestF28Rand(t *testing.T) {
	_, err := F2_8(0).Rand()
	if err != nil {
		t.Fatalf("Rand() returned error: %v", err)
	}
	// if got > 0xFF {
	// 	t.Fatalf("Rand() returned out-of-range value %#v", got)
	// }
}
