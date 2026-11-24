package protocol

// Byte-slice-in/byte-slice-out wrappers around Round1/Round2/Round3/
// Finalize (thmldsa44.go): each *Encoded function takes every other
// party's incoming round message pre-packed (via the PackRoundNMessage
// functions in marshalling.go) instead of already decoded, and returns its
// own outgoing message packed the same way, instead of as a
// RoundNMessage. This is what an actual network transport would hand
// these functions - real bytes in, real bytes out - rather than the
// already-unmarshalled Go values Round1/Round2/Round3/Finalize work with
// internally.
//
// Per-party state (Round1State/Round2State/Round3State) is never
// communicated between parties, so it's left typed rather than encoded -
// only the broadcast messages, and Finalize's final signature (which was
// already []byte), cross the wire.

import "fmt"

// Round1Encoded wraps Round1: same inputs, but its outgoing Round1Message
// comes back packed via PackRound1Message.
func Round1Encoded(keyState KeyState, preSign PreprocessingState, msg []byte) (error, Round1State, []byte) {
	err, r1State, r1Msg := Round1(keyState, preSign, msg)
	if err != nil {
		return err, Round1State{}, nil
	}
	return nil, r1State, PackRound1Message(r1Msg)
}

// Round2Encoded wraps Round2: r1MsgBytes holds every party's Round1Encoded
// output, one entry per party (in the same order Round2 itself expects),
// unpacked here via UnpackRound1Message before being handed to Round2. Its
// outgoing Round2Message comes back packed via PackRound2Message.
func Round2Encoded(keyState KeyState, preSign PreprocessingState, r1State Round1State, r1MsgBytes [][]byte) (error, Round2State, []byte) {
	r1Msgs := make([]Round1Message, len(r1MsgBytes))
	for i, b := range r1MsgBytes {
		m, err := UnpackRound1Message(b)
		if err != nil {
			return fmt.Errorf("protocol: unpacking r1Msgs[%d]: %w", i, err), Round2State{}, nil
		}
		r1Msgs[i] = m
	}

	err, r2State, r2Msg := Round2(keyState, preSign, r1State, r1Msgs)
	if err != nil {
		return err, Round2State{}, nil
	}
	return nil, r2State, PackRound2Message(r2Msg)
}

// Round3Encoded wraps Round3, mirroring Round2Encoded: r2MsgBytes holds
// every party's Round2Encoded output, unpacked via UnpackRound2Message; its
// outgoing Round3Message comes back packed via PackRound3Message.
func Round3Encoded(keyState KeyState, preSign PreprocessingState, r2State Round2State, r2MsgBytes [][]byte) (error, Round3State, []byte) {
	r2Msgs := make([]Round2Message, len(r2MsgBytes))
	for i, b := range r2MsgBytes {
		m, err := UnpackRound2Message(b)
		if err != nil {
			return fmt.Errorf("protocol: unpacking r2Msgs[%d]: %w", i, err), Round3State{}, nil
		}
		r2Msgs[i] = m
	}

	err, r3State, r3Msg := Round3(keyState, preSign, r2State, r2Msgs)
	if err != nil {
		return err, Round3State{}, nil
	}
	return nil, r3State, PackRound3Message(r3Msg)
}

// FinalizeEncoded wraps Finalize, mirroring Round2Encoded/Round3Encoded:
// r3MsgBytes holds every party's Round3Encoded output, unpacked via
// UnpackRound3Message. Finalize's own return value is already the raw
// signature bytes, so unlike Round1Encoded/Round2Encoded/Round3Encoded
// there's no outgoing message to pack.
func FinalizeEncoded(keyState KeyState, r3State Round3State, r3MsgBytes [][]byte) (error, []byte) {
	r3Msgs := make([]Round3Message, len(r3MsgBytes))
	for i, b := range r3MsgBytes {
		m, err := UnpackRound3Message(b)
		if err != nil {
			return fmt.Errorf("protocol: unpacking r3Msgs[%d]: %w", i, err), nil
		}
		r3Msgs[i] = m
	}

	return Finalize(keyState, r3State, r3Msgs)
}
