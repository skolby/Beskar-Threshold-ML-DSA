package protocol

import (
	"bytes"
	"io"
	"testing"
	"time"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	"t-mldsa/src/protocol/internal/wire"
	"t-mldsa/src/utils"
)

// TestRoundFlow is boilerplate wiring for the online phase: deal key and
// preprocessing state for each party, then drive every party through
// Round1 -> Round2 -> Round3 -> Finalize in sequence, collecting each
// round's per-party messages into a slice to hand to the next round (mirrors
// how the real protocol would broadcast one round's messages to everyone
// before starting the next). The round bodies are still stubs, so this only
// checks the plumbing compiles and runs end to end - it's a scaffold to
// extend as each round gets implemented.
//
// DealPreSig doesn't loop to only ever hand out an accepting (y, w0) pair -
// unlike a real signer, which would just resample and retry internally -
// so some fraction of draws are ones ML-DSA's own rejection sampling would
// have discarded. Finalize surfaces that as a decryption failure (the
// kPrime/keyOpenings-derived candidate key only recovers the real key when
// the draw was one that should be accepted), so this test always runs
// numAttempts independent draws of the whole round flow and tallies how many
// finalize (and verify) successfully, rather than stopping at the first
// success - a rejected draw isn't a bug, but zero successes out of
// numAttempts (expected acceptance rate ~23%) would be.
func TestRoundFlow(t *testing.T) {
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
		r1Msgs := make([]Round1Message, numShares)
		for i := range numShares {
			var err error
			err, r1States[i], r1Msgs[i] = Round1(keys[i], preSign[i], msg)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round1 failed: %v", attempt, i, err)
			}
		}

		// Round 2 - every party gets all of round 1's messages
		r2States := make([]Round2State, numShares)
		r2Msgs := make([]Round2Message, numShares)
		for i := range numShares {
			var err error
			err, r2States[i], r2Msgs[i] = Round2(keys[i], preSign[i], r1States[i], r1Msgs)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round2 failed: %v", attempt, i, err)
			}
		}

		// Round 3 - every party gets all of round 2's messages
		r3States := make([]Round3State, numShares)
		r3Msgs := make([]Round3Message, numShares)
		for i := range numShares {
			var err error
			err, r3States[i], r3Msgs[i] = Round3(keys[i], preSign[i], r2States[i], r2Msgs)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round3 failed: %v", attempt, i, err)
			}
		}

		// Finalize - every party gets all of round 3's messages
		sigs := make([][]byte, numShares)
		rejected := false
		for i := range numShares {
			var err error
			err, sigs[i] = Finalize(keys[i], r3States[i], r3Msgs)
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
		// resulting signature must actually verify against pk and msg -
		// mirrors Round2's own challenge-hashing closure (raw msg bytes,
		// no extra domain separation), since that's what produced c~.
		for i, sig := range sigs {
			if !mldsa44.Verify(pk, func(w io.Writer) { _, _ = w.Write(msg) }, sig) {
				t.Fatalf("attempt %d, party %d: Finalize's signature failed mldsa44.Verify", attempt, i)
			}
		}
		successes++
	}

	t.Logf("TestRoundFlow: %d/%d attempts produced a verifying signature", successes, numAttempts)
	if successes == 0 {
		t.Fatalf("0/%d attempts succeeded - expected some fraction (~23%%) to accept", numAttempts)
	}
}

// roundTiming accumulates per-call durations for one round function, split
// by whether the attempt they belong to ultimately accepted or was
// rejected - populated once per attempt, after that attempt's outcome is
// known, so a single roundTiming's accepted/rejected buckets stay
// consistent with each other.
type roundTiming struct {
	acceptedTotal time.Duration
	acceptedCount int
	rejectedTotal time.Duration
	rejectedCount int
}

// add records one attempt's calls to a round function: total is the summed
// duration of every one of the numShares per-party calls, count is how many
// calls that was (numShares, always, here) - added to the accepted or
// rejected bucket depending on accepted.
func (rt *roundTiming) add(accepted bool, total time.Duration, count int) {
	if accepted {
		rt.acceptedTotal += total
		rt.acceptedCount += count
	} else {
		rt.rejectedTotal += total
		rt.rejectedCount += count
	}
}

// avgPerCall returns the average duration of a single call in each bucket -
// zero if a bucket has no samples yet, rather than dividing by zero.
func (rt *roundTiming) avgPerCall() (accepted, rejected time.Duration) {
	if rt.acceptedCount > 0 {
		accepted = rt.acceptedTotal / time.Duration(rt.acceptedCount)
	}
	if rt.rejectedCount > 0 {
		rejected = rt.rejectedTotal / time.Duration(rt.rejectedCount)
	}
	return accepted, rejected
}

// milliseconds converts d to a float number of milliseconds, for printing
// every duration in TestRoundFlowBenchmark's report at the same fixed
// precision and unit regardless of magnitude - %v would otherwise switch
// between µs and ms across rows, making the columns not line up.
func milliseconds(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// TestRoundFlowBenchmark is a timing counterpart to TestRoundFlow: same
// round-flow wiring and numAttempts independent draws, but instead of
// asserting correctness it times every party's call to Round1, Round2,
// Round3 and Finalize, tallies the per-call average separately for attempts
// that accept and attempts a real signer's rejection sampling would have
// discarded (Finalize's decryption failure - see TestRoundFlow's doc
// comment), and prints the results. Round1/Round2/Round3 always succeed
// regardless of accept/reject (the draw's fate is only decided in Finalize),
// so any accepted-vs-rejected difference in their timing would be
// unexpected; Finalize's real work differs between the two (a rejected
// draw's decryption fails partway through), so it's the one most likely to
// show a difference.
func TestRoundFlowBenchmark(t *testing.T) {
	const threshold, numShares = 2, 5
	const numAttempts = 500
	msg := []byte("hello, threshold ML-DSA")

	pk, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}

	var round1, round2, round3, finalize roundTiming
	successes := 0

	for attempt := 1; attempt <= numAttempts; attempt++ {
		preSign, _, _, err := DealPreSig(threshold, numShares, pk)
		if err != nil {
			t.Fatalf("attempt %d: DealPreSig failed: %v", attempt, err)
		}

		// Round 1
		r1States := make([]Round1State, numShares)
		r1Msgs := make([]Round1Message, numShares)
		var round1Dur time.Duration
		for i := range numShares {
			start := time.Now()
			var err error
			err, r1States[i], r1Msgs[i] = Round1(keys[i], preSign[i], msg)
			round1Dur += time.Since(start)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round1 failed: %v", attempt, i, err)
			}
		}

		// Round 2 - every party gets all of round 1's messages
		r2States := make([]Round2State, numShares)
		r2Msgs := make([]Round2Message, numShares)
		var round2Dur time.Duration
		for i := range numShares {
			start := time.Now()
			var err error
			err, r2States[i], r2Msgs[i] = Round2(keys[i], preSign[i], r1States[i], r1Msgs)
			round2Dur += time.Since(start)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round2 failed: %v", attempt, i, err)
			}
		}

		// Round 3 - every party gets all of round 2's messages
		r3States := make([]Round3State, numShares)
		r3Msgs := make([]Round3Message, numShares)
		var round3Dur time.Duration
		for i := range numShares {
			start := time.Now()
			var err error
			err, r3States[i], r3Msgs[i] = Round3(keys[i], preSign[i], r2States[i], r2Msgs)
			round3Dur += time.Since(start)
			if err != nil {
				t.Fatalf("attempt %d, party %d: Round3 failed: %v", attempt, i, err)
			}
		}

		// Finalize - every party gets all of round 3's messages. Unlike
		// TestRoundFlow, every party's Finalize is timed even after one
		// rejects, rather than breaking out early, so the rejected bucket
		// gets numShares samples per attempt too.
		var finalizeDur time.Duration
		rejected := false
		for i := range numShares {
			start := time.Now()
			err, _ := Finalize(keys[i], r3States[i], r3Msgs)
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
		if accepted {
			successes++
		}
	}

	t.Logf("TestRoundFlowBenchmark: %d/%d attempts accepted", successes, numAttempts)
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
		t.Logf("%-8s  accepted: %10.4f ms/call (n=%3d)   rejected: %10.4f ms/call (n=%3d)",
			tc.name,
			milliseconds(acceptedAvg), tc.rt.acceptedCount,
			milliseconds(rejectedAvg), tc.rt.rejectedCount)
	}
}

// TestRound3EncryptsOpeningOfZ checks that Round3's ctxt - the opening of
// z_j it sends alongside kPrime/keyOpenings - actually is party i's z from
// Round2State, packed via wire.PackVecL and AES-GCM encrypted under that
// same party's own preSign.key: decrypting it under the right key must
// recover exactly the packed z, and decrypting under any other party's key
// must fail.
func TestRound3EncryptsOpeningOfZ(t *testing.T) {
	const threshold, numShares = 2, 5
	msg := []byte("hello, threshold ML-DSA")

	pk, keys, err := DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	preSign, _, _, err := DealPreSig(threshold, numShares, pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}

	r1States := make([]Round1State, numShares)
	r1Msgs := make([]Round1Message, numShares)
	for i := range numShares {
		var err error
		err, r1States[i], r1Msgs[i] = Round1(keys[i], preSign[i], msg)
		if err != nil {
			t.Fatalf("party %d Round1 failed: %v", i, err)
		}
	}

	r2States := make([]Round2State, numShares)
	r2Msgs := make([]Round2Message, numShares)
	for i := range numShares {
		var err error
		err, r2States[i], r2Msgs[i] = Round2(keys[i], preSign[i], r1States[i], r1Msgs)
		if err != nil {
			t.Fatalf("party %d Round2 failed: %v", i, err)
		}
	}

	r3Msgs := make([]Round3Message, numShares)
	for i := range numShares {
		var err error
		_, _, r3Msgs[i] = Round3(keys[i], preSign[i], r2States[i], r2Msgs)
		if err != nil {
			t.Fatalf("party %d Round3 failed: %v", i, err)
		}
	}

	for i := range numShares {
		wantZ := wire.PackVecL(r2States[i].z)

		got, err := utils.Decrypt(preSign[i].key[:], r3Msgs[i].ctxt)
		if err != nil {
			t.Fatalf("party %d: Decrypt(own key, ctxt) failed: %v", i, err)
		}
		if !bytes.Equal(got, wantZ) {
			t.Fatalf("party %d: decrypted ctxt != PackVecL(z)", i)
		}

		// Sanity check the encryption is actually keyed on this party's own
		// key - decrypting under a different party's key must fail.
		other := (i + 1) % numShares
		if _, err := utils.Decrypt(preSign[other].key[:], r3Msgs[i].ctxt); err == nil {
			t.Fatalf("party %d: Decrypt(other party %d's key, ctxt) unexpectedly succeeded", i, other)
		}
	}
}
