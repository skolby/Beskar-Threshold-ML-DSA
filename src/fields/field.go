package fields

import "errors"

type FieldElement[T any] interface {
	comparable
	FromUint(uint32) T
	Zero() T
	Rand() (T, error)
	Add(T) T
	Sub(T) T
	Mult(T) T
	Inv() T
	// PartyPoint returns the Shamir interpolation point (x-coordinate) for the given party.
	PartyPoint(partyID int) T
}

const maxNumTries = 64

var (
	ErrMaxNumTries = errors.New("random rejection sampling reached maximum number of tries")
)
