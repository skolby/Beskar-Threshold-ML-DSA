// mldsa implements NIST post-quantum signature scheme ML-DSA (FIPS204)
//
// Each of the three different security levels of ML-DSA is implemented by a
// subpackage. For instance, mldsa44 can be found in
//
//	t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44
//
// If your choice for mode is fixed compile-time, use the subpackages.
// To choose a scheme at runtime, use the generic signatures API under
//
//	t-mldsa/src/circl-mldsa/sign/schemes
package mldsa
