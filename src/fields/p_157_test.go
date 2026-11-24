package fields

import "testing"

func TestZ157FromUintAndZero(t *testing.T) {
	cases := []struct {
		name string
		in   uint32
		want Z157
	}{
		{name: "zero", in: 0, want: Z157(0)},
		{name: "one", in: 1, want: Z157(1)},
		{name: "max", in: 156, want: Z157(156)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Z157(0).FromUint(tc.in); got != tc.want {
				t.Fatalf("FromUint(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}

	if got := Z157(0).Zero(); got != Z157(0) {
		t.Fatalf("Zero() = %d, want 0", got)
	}
}

func TestZ157FromUintReducesOutOfRange(t *testing.T) {
	cases := []struct {
		in   uint32
		want Z157
	}{
		{in: 157, want: Z157(0)},
		{in: 158, want: Z157(1)},
		{in: 314, want: Z157(0)},
		{in: ^uint32(0), want: Z157(92)},
	}

	for _, tc := range cases {
		if got := Z157(0).FromUint(tc.in); got != tc.want {
			t.Fatalf("FromUint(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestZ157Add(t *testing.T) {
	tests := []struct {
		name string
		x    Z157
		y    Z157
		want Z157
	}{
		{name: "simple", x: Z157(2), y: Z157(3), want: Z157(5)},
		{name: "wrap", x: Z157(156), y: Z157(2), want: Z157(1)},
		{name: "zero", x: Z157(0), y: Z157(42), want: Z157(42)},
		{name: "self", x: Z157(10), y: Z157(10), want: Z157(20)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.Add(tt.y); got != tt.want {
				t.Fatalf("Add(%d, %d) = %d, want %d", tt.x, tt.y, got, tt.want)
			}
		})
	}
}

func TestZ157Sub(t *testing.T) {
	tests := []struct {
		name string
		x    Z157
		y    Z157
		want Z157
	}{
		{name: "simple", x: Z157(10), y: Z157(3), want: Z157(7)},
		{name: "wrap", x: Z157(2), y: Z157(3), want: Z157(156)},
		{name: "zero", x: Z157(42), y: Z157(0), want: Z157(42)},
		{name: "self", x: Z157(13), y: Z157(13), want: Z157(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.Sub(tt.y); got != tt.want {
				t.Fatalf("Sub(%d, %d) = %d, want %d", tt.x, tt.y, got, tt.want)
			}
		})
	}
}

func TestZ157Mult(t *testing.T) {
	tests := []struct {
		name string
		x    Z157
		y    Z157
		want Z157
	}{
		{name: "simple", x: Z157(156), y: Z157(156), want: Z157(1)},
		{name: "mod-reduction", x: Z157(1), y: Z157(17), want: Z157(17)},
		{name: "zero", x: Z157(43), y: Z157(0), want: Z157(0)},
		{name: "identity", x: Z157(7), y: Z157(1), want: Z157(7)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.x.Mult(tt.y); got != tt.want {
				t.Fatalf("Mult(%d, %d) = %d, want %d", tt.x, tt.y, got, tt.want)
			}
		})
	}
}

func TestZ157Inv(t *testing.T) {
	tests := []struct {
		name string
		in   Z157
		want Z157
	}{
		{name: "one", in: Z157(1), want: Z157(1)},
		{name: "two", in: Z157(2), want: Z157(79)},
		{name: "ten", in: Z157(10), want: Z157(110)},
		{name: "minus-one", in: Z157(156), want: Z157(156)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.Inv(); got != tt.want {
				t.Fatalf("Inv(%d) = %d, want %d", tt.in, got, tt.want)
			}
			if got := tt.in.Mult(tt.in.Inv()); got != Z157(1) {
				t.Fatalf("Inv(%d) * %d = %d, want 1", tt.in, tt.in, got)
			}
		})
	}
}

func TestZ157Rand(t *testing.T) {
	for range 32 {
		r, err := Z157(0).Rand()
		if err != nil {
			t.Fatalf("Rand() failed: %v", err)
		}
		if r >= Z157(P) {
			t.Fatalf("Rand() returned %d, want value in [0, %d)", r, P)
		}
	}
}
