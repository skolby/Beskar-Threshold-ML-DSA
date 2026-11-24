package protocol

import (
	"fmt"
	"io"
	"testing"
	"time"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
)

// TestRoundFlowEncoded mirrors TestRoundFlow (thmldsa44_test.go), driving
// every party through Round1Encoded -> Round2Encoded -> Round3Encoded ->
// FinalizeEncoded instead of the unwrapped rounds - i.e. every message
// collected into the slice handed to the next round is now the packed
// []byte a real transport would actually carry, round-tripped through
// UnpackRoundNMessage inside the next round's *Encoded call, rather than
// the already-decoded RoundNMessage value itself. This checks the
// encode/decode wrapping is transparent to the protocol: it should accept
// and produce verifying signatures at the same rate as the unwrapped round
// flow.
func TestRoundFlowEncoded(t *testing.T) {
	const threshold, numShares = 2, 5
	const numAttempts = 100
	msg := []byte("hello, threshold ML-DSA")

	pk, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	successes := 0
	for attempt := 1; attempt <= numAttempts; attempt++ {
		preSign, _, _, err := DealPreSig(threshold, numShares, pk)
		if err != nil {
			t.Fatalf("attempt %d: DealPreSig failed: %v", attempt, err)
		}

		// Round 1
		r1States := make([]Round1State, numShares)
		r1MsgBytes := make([][]byte, numShares)
		for i := range numShares {
			var err error
			err, r1States[i], r1MsgBytes[i] = Round1Encoded(keys[i], preSign[i], msg)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round1Encoded failed: %v", attempt, i, err)
			}
		}

		// Round 2 - every party gets all of round 1's packed messages
		r2States := make([]Round2State, numShares)
		r2MsgBytes := make([][]byte, numShares)
		for i := range numShares {
			var err error
			err, r2States[i], r2MsgBytes[i] = Round2Encoded(keys[i], preSign[i], r1States[i], r1MsgBytes)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round2Encoded failed: %v", attempt, i, err)
			}
		}

		// Round 3 - every party gets all of round 2's packed messages
		r3States := make([]Round3State, numShares)
		r3MsgBytes := make([][]byte, numShares)
		for i := range numShares {
			var err error
			err, r3States[i], r3MsgBytes[i] = Round3Encoded(keys[i], preSign[i], r2States[i], r2MsgBytes)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round3Encoded failed: %v", attempt, i, err)
			}
		}

		// Finalize - every party gets all of round 3's packed messages
		sigs := make([][]byte, numShares)
		rejected := false
		for i := range numShares {
			var err error
			err, sigs[i] = FinalizeEncoded(keys[i], r3States[i], r3MsgBytes)
			if err != nil {
				// Expected outcome of a draw that should have been rejected
				// - move on to the next attempt, as a real signer would.
				rejected = true
				break
			}
		}
		if rejected {
			continue
		}

		// Every party reconstructed and finalized independently; each
		// resulting signature must actually verify against pk and msg.
		for i, sig := range sigs {
			if !mldsa44.Verify(pk, func(w io.Writer) { _, _ = w.Write(msg) }, sig) {
				t.Fatalf("attempt %d, party %d: FinalizeEncoded's signature failed mldsa44.Verify", attempt, i)
			}
		}
		successes++
	}

	t.Logf("TestRoundFlowEncoded: %d/%d attempts produced a verifying signature", successes, numAttempts)
	if successes == 0 {
		t.Fatalf("0/%d attempts succeeded - expected some fraction (~23%%) to accept", numAttempts)
	}
}

// commsTally accumulates per-party outgoing message sizes, in bytes, for
// one round - split by whether the attempt they belong to ultimately
// accepted or was rejected, exactly like roundTiming (thmldsa44_test.go)
// does for durations. Kept as a separate type from roundTiming, rather than
// generalizing over time.Duration/int, since the two are populated and
// reported differently (avgPerCall divides by a count either way, but the
// unit and print formatting differ).
type commsTally struct {
	acceptedBytes int
	acceptedCount int
	rejectedBytes int
	rejectedCount int
}

// add records one attempt's messages for a round: total is the summed
// packed size of every one of the numShares per-party outgoing messages,
// count is how many messages that was (numShares, always, here) - added to
// the accepted or rejected bucket depending on accepted.
func (ct *commsTally) add(accepted bool, total int, count int) {
	if accepted {
		ct.acceptedBytes += total
		ct.acceptedCount += count
	} else {
		ct.rejectedBytes += total
		ct.rejectedCount += count
	}
}

// avgPerCall returns the average packed message size of a single party in
// each bucket - zero if a bucket has no samples yet, rather than dividing
// by zero.
func (ct *commsTally) avgPerCall() (accepted, rejected float64) {
	if ct.acceptedCount > 0 {
		accepted = float64(ct.acceptedBytes) / float64(ct.acceptedCount)
	}
	if ct.rejectedCount > 0 {
		rejected = float64(ct.rejectedBytes) / float64(ct.rejectedCount)
	}
	return accepted, rejected
}

// runRoundFlowBenchmarkEncoded is TestRoundFlowBenchmark's
// (thmldsa44_test.go) counterpart for the *Encoded wrappers: same round-flow
// wiring, numAttempts independent draws, and per-round timing (now measured
// on Round1Encoded/Round2Encoded/Round3Encoded/FinalizeEncoded instead of
// the unwrapped rounds), but it additionally tallies each round's per-party
// communication cost - the packed size, in bytes, of the one message each
// party sends that round - falling out for free since the *Encoded
// functions already hand back that message as bytes.
//
// Round1/Round2/Round3's messages are a fixed size for a given (threshold,
// numShares) - they don't depend on the draw at all (see marshalling.go) -
// so, like their timings, their accepted/rejected byte averages are
// expected to come out identical; any difference would be unexpected.
// Finalize never broadcasts a message of its own (its output is each
// party's local final signature, not something sent to the other parties),
// so it has no communication entry, only a timing one.
//
// Factored out of a single (threshold, numShares) so the same measurement
// can be run across several group sizes - see TestRoundFlowBenchmarkEncoded
// and TestRoundFlowBenchmarkEncodedAcrossThresholds.
func runRoundFlowBenchmarkEncoded(t *testing.T, threshold, numShares, numAttempts int) {
	t.Helper()
	msg := []byte("hello, threshold ML-DSA")

	pk, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	var round1, round2, round3, finalize roundTiming
	var comms1, comms2, comms3, commsTotal commsTally
	successes := 0

	for attempt := 1; attempt <= numAttempts; attempt++ {
		preSign, _, _, err := DealPreSig(threshold, numShares, pk)
		if err != nil {
			t.Fatalf("attempt %d: DealPreSig failed: %v", attempt, err)
		}

		// Round 1
		r1States := make([]Round1State, numShares)
		r1MsgBytes := make([][]byte, numShares)
		var round1Dur time.Duration
		round1Bytes := 0
		for i := range numShares {
			start := time.Now()
			var err error
			err, r1States[i], r1MsgBytes[i] = Round1Encoded(keys[i], preSign[i], msg)
			round1Dur += time.Since(start)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round1Encoded failed: %v", attempt, i, err)
			}
			round1Bytes += len(r1MsgBytes[i])
		}

		// Round 2 - every party gets all of round 1's packed messages
		r2States := make([]Round2State, numShares)
		r2MsgBytes := make([][]byte, numShares)
		var round2Dur time.Duration
		round2Bytes := 0
		for i := range numShares {
			start := time.Now()
			var err error
			err, r2States[i], r2MsgBytes[i] = Round2Encoded(keys[i], preSign[i], r1States[i], r1MsgBytes)
			round2Dur += time.Since(start)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round2Encoded failed: %v", attempt, i, err)
			}
			round2Bytes += len(r2MsgBytes[i])
		}

		// Round 3 - every party gets all of round 2's packed messages
		r3States := make([]Round3State, numShares)
		r3MsgBytes := make([][]byte, numShares)
		var round3Dur time.Duration
		round3Bytes := 0
		for i := range numShares {
			start := time.Now()
			var err error
			err, r3States[i], r3MsgBytes[i] = Round3Encoded(keys[i], preSign[i], r2States[i], r2MsgBytes)
			round3Dur += time.Since(start)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round3Encoded failed: %v", attempt, i, err)
			}
			round3Bytes += len(r3MsgBytes[i])
		}

		// Finalize - every party gets all of round 3's packed messages.
		// Unlike TestRoundFlowEncoded, every party's FinalizeEncoded is timed
		// even after one rejects, rather than breaking out early, so the
		// rejected bucket gets numShares samples per attempt too - mirrors
		// TestRoundFlowBenchmark. No communication tally here: Finalize
		// doesn't produce a message sent to the other parties.
		var finalizeDur time.Duration
		rejected := false
		for i := range numShares {
			start := time.Now()
			err, _ := FinalizeEncoded(keys[i], r3States[i], r3MsgBytes)
			finalizeDur += time.Since(start)
			if err != nil {
				rejected = true
			}
		}

		accepted := !rejected
		round1.add(accepted, round1Dur, numShares)
		round2.add(accepted, round2Dur, numShares)
		round3.add(accepted, round3Dur, numShares)
		finalize.add(accepted, finalizeDur, numShares)
		comms1.add(accepted, round1Bytes, numShares)
		comms2.add(accepted, round2Bytes, numShares)
		comms3.add(accepted, round3Bytes, numShares)
		commsTotal.add(accepted, round1Bytes+round2Bytes+round3Bytes, numShares)
		if accepted {
			successes++
		}
	}

	t.Logf("threshold=%d numShares=%d: %d/%d attempts accepted", threshold, numShares, successes, numAttempts)

	timings := []struct {
		name string
		rt   *roundTiming
	}{
		{"Round1", &round1},
		{"Round2", &round2},
		{"Round3", &round3},
		{"Finalize", &finalize},
	}
	for _, tc := range timings {
		acceptedAvg, rejectedAvg := tc.rt.avgPerCall()
		t.Logf("%-8s  accepted: %10.4f ms/call  (n=%3d)   rejected: %10.4f ms/call  (n=%3d)",
			tc.name,
			milliseconds(acceptedAvg), tc.rt.acceptedCount,
			milliseconds(rejectedAvg), tc.rt.rejectedCount)
	}

	comms := []struct {
		name string
		ct   *commsTally
	}{
		{"Round1", &comms1},
		{"Round2", &comms2},
		{"Round3", &comms3},
		{"Total", &commsTotal},
	}
	for _, tc := range comms {
		acceptedAvg, rejectedAvg := tc.ct.avgPerCall()
		t.Logf("%-8s  accepted: %10.1f B/party  (n=%3d)   rejected: %10.1f B/party  (n=%3d)",
			tc.name,
			acceptedAvg, tc.ct.acceptedCount,
			rejectedAvg, tc.ct.rejectedCount)
	}
}

// TestRoundFlowBenchmarkEncoded runs runRoundFlowBenchmarkEncoded at a
// single, arbitrary (threshold, numShares) - see
// TestRoundFlowBenchmarkEncodedAcrossThresholds for the same measurement
// run across several group sizes.
func TestRoundFlowBenchmarkEncoded(t *testing.T) {
	const threshold, numShares = 2, 5
	const numAttempts = 100
	runRoundFlowBenchmarkEncoded(t, threshold, numShares, numAttempts)
}

func TestRoundFlowBenchmarkLarge(t *testing.T) {
	const threshold, numShares = 31, 63
	const numAttempts = 100
	runRoundFlowBenchmarkEncoded(t, threshold, numShares, numAttempts)
}

// TestRoundFlowBenchmarkEncodedAcrossThresholds runs
// runRoundFlowBenchmarkEncoded once per (threshold, numShares) below, each
// as its own subtest, to see how per-round timing and communication scale
// with the group size - a small group (1-of-3), a mid-sized one (3-of-7),
// and a larger one (7-of-15).
func TestRoundFlowBenchmarkEncodedAcrossThresholds(t *testing.T) {
	const numAttempts = 20

	configs := []struct {
		threshold, numShares int
	}{
		{1, 3},
		{2, 5},
		{3, 7},
		{7, 15},
	}
	for _, c := range configs {
		t.Run(fmt.Sprintf("threshold=%d,numShares=%d", c.threshold, c.numShares), func(t *testing.T) {
			runRoundFlowBenchmarkEncoded(t, c.threshold, c.numShares, numAttempts)
		})
	}
}
