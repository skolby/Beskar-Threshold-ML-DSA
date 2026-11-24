package secretsharing

import (
	"t-mldsa/src/fields"
	"testing"
)

func TestShare(t *testing.T) {
	// Test with a simple case
	secret := fields.Z157(0).FromUint(5)
	threshold := 3
	numShares := 5

	shares := Share(secret, threshold, numShares)
	if len(shares) != numShares {
		t.Errorf("Expected %d shares, got %d", numShares, len(shares))
	}

	// Additional tests can be added here to verify the correctness of the shares
}

func TestReconstruct(t *testing.T) {
	// Test with a simple case
	secret := fields.Z157(0).FromUint(10)
	threshold := 3
	numShares := 5

	shares := Share(secret, threshold, numShares)
	reconstructedSecret, err := Reconstruct(shares[:], threshold, numShares)
	if err != nil {
		t.Errorf("Error reconstructing secret: %v", err)
	}
	if reconstructedSecret != secret {
		t.Errorf("Expected secret %v, got %v", secret, reconstructedSecret)
	}

	// Additional tests can be added here to verify the correctness of the reconstruction
}

func TestReconstructExplicitShares(t *testing.T) {
	// Explicit deterministic shares from f(x)=42+7x+3x^2 mod 157 at x=1..5:
	// [52,68,90,118,152]. Reconstruct should recover 42.
	threshold := 3
	numShares := 5
	shares := []fields.Z157{
		fields.Z157(0).FromUint(52),
		fields.Z157(0).FromUint(68),
		fields.Z157(0).FromUint(90),
		fields.Z157(0).FromUint(118),
		fields.Z157(0).FromUint(152),
	}

	reconstructedSecret, err := Reconstruct(shares, threshold, numShares)
	if err != nil {
		t.Fatalf("Error reconstructing explicit shares: %v", err)
	}

	want := fields.Z157(0).FromUint(42)
	if reconstructedSecret != want {
		t.Fatalf("Expected secret %v, got %v", want, reconstructedSecret)
	}
}

func TestReconstructError(t *testing.T) {
	// Test with a simple case
	secret := fields.Z157(0).FromUint(10)
	threshold := 3
	numShares := 5

	shares := Share(secret, threshold, numShares)
	shares[2] = shares[2].FromUint(99) // Corrupt one share
	_, err := Reconstruct(shares[:], threshold, numShares)
	if err == nil {
		t.Fatalf("Expected error but got none")
	}
}

// TestReconstructLiftedF2_8SharesInF2_128 regression-tests the bug
// PartyPoint fixes: an F2_8 secret is Shamir-shared in F2_8, each share is
// lifted into F2_128 via ToF2_128 (mirroring package protocol's
// randLinComb, which lifts F2_8 LUT-check shares this way before combining
// them into an F2_128 value), and the lifted shares are reconstructed as
// F2_128 shares. Since ToF2_128 is a field embedding and F2_128's
// PartyPoint is derived from F2_8's own PartyPoint, this must succeed and
// recover exactly the lifted secret - before PartyPoint existed, Reconstruct
// used FromUint(partyID) as the interpolation point for every field, which
// is the wrong x-coordinate for a lifted F2_8 share and made this fail.
func TestReconstructLiftedF2_8SharesInF2_128(t *testing.T) {
	threshold := 3
	numShares := 5

	secret := fields.F2_8(0x53)
	f2_8Shares := Share(secret, threshold, numShares)

	liftedShares := make([]fields.F2_128, numShares)
	for i, s := range f2_8Shares {
		liftedShares[i] = s.ToF2_128()
	}

	got, err := Reconstruct(liftedShares, threshold, numShares)
	if err != nil {
		t.Fatalf("Reconstruct(lifted F2_8 shares) failed: %v", err)
	}
	want := secret.ToF2_128()
	if got != want {
		t.Fatalf("Reconstruct(lifted F2_8 shares) = %+v, want %+v (secret.ToF2_128())", got, want)
	}
}

func TestReconstructErrorExplicitShares(t *testing.T) {
	// Explicit deterministic shares from f(x)=42+7x+3x^2 mod 157 at x=1..5:
	// [52,68,90,118,152]. Reconstruct should recover 42.
	threshold := 3
	numShares := 5
	shares := []fields.Z157{
		fields.Z157(0).FromUint(52),
		fields.Z157(0).FromUint(68),
		fields.Z157(0).FromUint(4),
		fields.Z157(0).FromUint(118),
		fields.Z157(0).FromUint(152),
	}

	_, err := Reconstruct(shares, threshold, numShares)
	if err == nil {
		t.Fatalf("Expected error but got none")
	}

}
