package fields

import "testing"

func TestZQFromUintAndZero(t *testing.T) {
	if got := ZQ(0).FromUint(0); got != ZQ(0) {
		t.Fatalf("FromUint(0) = %d, want 0", got)
	}
	if got := ZQ(0).FromUint(Q - 1); got != ZQ(Q-1) {
		t.Fatalf("FromUint(Q-1) = %d, want %d", got, Q-1)
	}
	if got := ZQ(0).Zero(); got != ZQ(0) {
		t.Fatalf("Zero() = %d, want 0", got)
	}
}

func TestZQFromUintPanicsOnOutOfRange(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("FromUint(Q) should panic")
		}
	}()
	_ = ZQ(0).FromUint(Q)
}

func TestZQAddSubMultVectors(t *testing.T) {
	tests := []struct {
		name    string
		x       ZQ
		y       ZQ
		wantAdd ZQ
		wantSub ZQ
		wantMul ZQ
	}{
		{
			name:    "small",
			x:       ZQ(2),
			y:       ZQ(3),
			wantAdd: ZQ(5),
			wantSub: ZQ(Q - 1),
			wantMul: ZQ(6),
		},
		{
			name:    "wrap-add",
			x:       ZQ(Q - 1),
			y:       ZQ(2),
			wantAdd: ZQ(1),
			wantSub: ZQ(Q - 3),
			wantMul: ZQ(Q - 2),
		},
		{
			name:    "zero",
			x:       ZQ(0),
			y:       ZQ(12345),
			wantAdd: ZQ(12345),
			wantSub: ZQ(Q - 12345),
			wantMul: ZQ(0),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.x.Add(tc.y); got != tc.wantAdd {
				t.Fatalf("Add(%d, %d) = %d, want %d", tc.x, tc.y, got, tc.wantAdd)
			}
			if got := tc.x.Sub(tc.y); got != tc.wantSub {
				t.Fatalf("Sub(%d, %d) = %d, want %d", tc.x, tc.y, got, tc.wantSub)
			}
			if got := tc.x.Mult(tc.y); got != tc.wantMul {
				t.Fatalf("Mult(%d, %d) = %d, want %d", tc.x, tc.y, got, tc.wantMul)
			}
		})
	}
}

func TestZQInvKnownValues(t *testing.T) {
	tests := []struct {
		name string
		x    ZQ
		want ZQ
	}{
		{name: "one", x: ZQ(1), want: ZQ(1)},
		{name: "minus-one", x: ZQ(Q - 1), want: ZQ(Q - 1)},
		{name: "two", x: ZQ(2), want: ZQ((Q + 1) / 2)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.x.Inv(); got != tc.want {
				t.Fatalf("Inv(%d) = %d, want %d", tc.x, got, tc.want)
			}
		})
	}
}

func TestZQInvIdentity(t *testing.T) {
	values := []ZQ{1, 2, 3, 5, 7, 12345, ZQ(Q - 2), ZQ(Q - 1)}
	for _, x := range values {
		inv := x.Inv()
		if got := x.Mult(inv); got != ZQ(1) {
			t.Fatalf("x*Inv(x) failed for x=%d: got %d", x, got)
		}
		if got := inv.Mult(x); got != ZQ(1) {
			t.Fatalf("Inv(x)*x failed for x=%d: got %d", x, got)
		}
	}
}
