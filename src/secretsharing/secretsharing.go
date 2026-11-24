package secretsharing

import (
	"fmt"
	"t-mldsa/src/fields"
)

// Shamir Shares a secret in field T with numShares shares, so t or fewer shares reveal nothing about the secret.
func Share[T fields.FieldElement[T]](secret T, threshold int, numShares int) []T {
	if threshold >= numShares {
		panic("threshold must be less than the number of shares, or threshold+1 shares could never be gathered to reconstruct")
	}
	// Pick random coefficients for the degree-threshold polynomial
	coefficients := make([]T, threshold+1)
	coefficients[0] = secret
	for i := 1; i <= threshold; i++ {
		var err error
		coefficients[i], err = coefficients[i].Rand()
		if err != nil {
			panic(err)
		}
	}

	// Evaluate the polynomial at each party's interpolation point to produce the shares.
	// A field defines its own interpolation points.
	shares := make([]T, numShares)
	for i := 0; i < numShares; i++ {
		x := secret.PartyPoint(i + 1)
		y := polyEval(coefficients, x)
		shares[i] = y
	}
	return shares
}

// Can be replaced with Horner's method for greater efficiency.
func polyEval[T fields.FieldElement[T]](coeffs []T, x T) T {
	y := coeffs[0]
	xPow := x
	for _, v := range coeffs[1:] {
		y = y.Add(xPow.Mult(v)) // y += c_i x^i
		xPow = xPow.Mult(x)     // x^{i+1} = x^i * x
	}
	return y
}

// Building a reconstructor allows preprocessing interpolation coefficients so they don't need to be recomputed for each reconstruction.
type Reconstructor[T fields.FieldElement[T]] struct {
	threshold int
	numShares int
	// Coefficients for interpolating the secret using the first threshold+1 shares.
	secretCoeffs []T
	// Coefficients for interpolating remaining shares based on the first threshold+1 shares, to allow for constistency checks.
	checkCoeffs [][]T
}

// Produce a reconstructor by precomputing interpolation coefficients
func NewReconstructor[T fields.FieldElement[T]](threshold int, numShares int) *Reconstructor[T] {
	if numShares < threshold+1 {
		panic("not enough shares to reconstruct the secret")
	}

	var zero T
	// Get a list of the first t+1 interpolation points
	nodes := interpolationPoints[T](threshold + 1)
	denomInv := lagrangeDenominators(nodes)
	for j, d := range denomInv {
		denomInv[j] = d.Inv()
	}

	// Get coefficients for interpolating constant term
	secretCoeffs := lagrangeCoeffsAt(zero, nodes, denomInv)

	// Coefficients for points t+1,...,n
	checkCoeffs := make([][]T, numShares-(threshold+1))
	for k := range checkCoeffs {
		i := threshold + 1 + k
		checkCoeffs[k] = lagrangeCoeffsAt(zero.PartyPoint(i+1), nodes, denomInv)
	}

	return &Reconstructor[T]{
		threshold:    threshold,
		numShares:    numShares,
		secretCoeffs: secretCoeffs,
		checkCoeffs:  checkCoeffs,
	}
}

// Reconstruct secret given all shares, returns an error if any shares are inconsistent.
func (r *Reconstructor[T]) Reconstruct(shares []T) (T, error) {
	if len(shares) != r.numShares {
		return *new(T), fmt.Errorf("expected exactly %d shares, got %d", r.numShares, len(shares))
	}

	// Recover Secret.
	secret := shares[0].Zero()
	for i, c := range r.secretCoeffs {
		secret = secret.Add(shares[i].Mult(c))
	}

	// Check remaining shares for consistency.
	for k, coeffs := range r.checkCoeffs {
		i := r.threshold + 1 + k
		share_ := shares[0].Zero()
		for j, c := range coeffs {
			share_ = share_.Add(shares[j].Mult(c))
		}
		if share_ != shares[i] {
			return *new(T), fmt.Errorf("share %d is inconsistent with the first %d shares", i+1, r.threshold+1)
		}
	}
	return secret, nil
}

// Extra function to allow direct reconstruction, implicitly producing a reconstructor
func Reconstruct[T fields.FieldElement[T]](shares []T, threshold int, numShares int) (T, error) {
	if len(shares) != numShares {
		return *new(T), fmt.Errorf("expected exactly %d shares, got %d", numShares, len(shares))
	}
	return NewReconstructor[T](threshold, numShares).Reconstruct(shares)
}

// Get a slice of the first numPoints interpolation points
func interpolationPoints[T fields.FieldElement[T]](numPoints int) []T {
	var zero T
	nodes := make([]T, numPoints)
	for j := range numPoints {
		nodes[j] = zero.PartyPoint(j + 1)
	}
	return nodes
}

// lagrangeDenominators returns, for each point, the product of its
// differences from every other point: out[j] = prod_{k!=j} (interpolationPoints[j]-interpolationPoints[k]).
func lagrangeDenominators[T fields.FieldElement[T]](interpolationPoints []T) []T {
	denominators := make([]T, len(interpolationPoints))
	for j, nodeJ := range interpolationPoints {
		d := nodeJ.FromUint(1)
		for k, nodeK := range interpolationPoints {
			if k == j {
				continue
			}
			d = d.Mult(nodeJ.Sub(nodeK)) // d *= (interpolationPoints[j] - interpolationPoints[k])
		}
		denominators[j] = d
	}
	return denominators
}

// lagrangeCoeffsAt computes L_0(x)..L_{len(nodes)-1}(x), the Lagrange basis
// coefficients of nodes evaluated at x, given the precomputed,
// inverted output of lagrangeDenominators(nodes).
func lagrangeCoeffsAt[T fields.FieldElement[T]](x T, nodes []T, denomInv []T) []T {
	diffs := make([]T, len(nodes))
	for k, node := range nodes {
		diffs[k] = x.Sub(node)
	}
	numerators := productsExcludingSelf(diffs)

	coeffs := make([]T, len(nodes))
	for j := range nodes {
		coeffs[j] = numerators[j].Mult(denomInv[j])
	}
	return coeffs
}

// productsExcludingSelf returns, for each index i, the product of every
// element of vs except vs[i]: out[i] = prod_{k!=i} vs[k].
func productsExcludingSelf[T fields.FieldElement[T]](vs []T) []T {
	n := len(vs)
	out := make([]T, n)
	if n == 0 {
		return out
	}
	one := vs[0].FromUint(1)

	// prefix[i] = prod(vs[:i])
	prefix := make([]T, n+1)
	prefix[0] = one
	for i, v := range vs {
		prefix[i+1] = prefix[i].Mult(v)
	}

	// suffix accumulates prod(vs[i+1:]) as i decreases.
	suffix := one
	for i := n - 1; i >= 0; i-- {
		out[i] = prefix[i].Mult(suffix)
		suffix = suffix.Mult(vs[i])
	}
	return out
}
