package network

// network_test.go is the local-loopback end-to-end test harness: every
// party runs as a real libp2p host (loopback TCP, real streams, real
// security/muxing - the full network stack), each as an independent
// goroutine running RunLeader or RunPeer exactly as a separate process
// would (see cmd/tmldsa-network) - connecting only via the addresses it's
// given, never reaching into another party's state directly.

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
)

// newTestHosts creates n real libp2p hosts on loopback TCP. Registers
// cleanup to close every host when t ends.
func newTestHosts(t *testing.T, n int) []host.Host {
	t.Helper()

	hosts := make([]host.Host, n)
	for i := range hosts {
		h, err := NewHost()
		if err != nil {
			t.Fatalf("NewHost: %v", err)
		}
		hosts[i] = h
	}
	t.Cleanup(func() {
		for _, h := range hosts {
			_ = h.Close()
		}
	})
	return hosts
}

// runBatch runs one leader (hosts[0]) and one peer per remaining host,
// each its own goroutine, and returns once the leader's run - every
// repeat - finishes and every peer has seen it finish.
func runBatch(t *testing.T, ctx context.Context, hosts []host.Host, threshold, numSessions, repeats int, msg []byte) (*mldsa44.PublicKey, RunSummary, error) {
	t.Helper()
	numShares := len(hosts)

	peers := make([]*Party, numShares-1)
	peerErrs := make([]error, numShares-1)
	var wg sync.WaitGroup
	for i := 1; i < numShares; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			connect := make([]peer.AddrInfo, i)
			for j := 0; j < i; j++ {
				connect[j] = peer.AddrInfo{ID: hosts[j].ID(), Addrs: hosts[j].Addrs()}
			}
			p, err := RunPeer(ctx, hosts[i], numShares, connect)
			if err != nil {
				peerErrs[i-1] = err
				return
			}
			peers[i-1] = p
		}(i)
	}

	pk, summary, err := RunLeader(ctx, hosts[0], numShares, threshold, numSessions, repeats, msg)
	wg.Wait()

	for i, perr := range peerErrs {
		if perr != nil {
			t.Fatalf("RunPeer (party %d) failed: %v", i+2, perr)
		}
	}
	if err != nil {
		return pk, summary, err
	}

	for i, p := range peers {
		select {
		case <-p.Finished():
		case <-p.Context().Done():
			t.Fatalf("party %d aborted instead of finishing: %v", i+2, context.Cause(p.Context()))
		case <-time.After(10 * time.Second):
			t.Fatalf("party %d never saw the run finish", i+2)
		}
	}
	return pk, summary, nil
}

// TestRunBatchLocalLoopback runs one repeat of a batch of parallel
// sessions over real libp2p hosts and checks: every session reaches a
// terminal outcome, every accepted signature verifies, and the reported
// timing is sane.
func TestRunBatchLocalLoopback(t *testing.T) {
	const threshold, numShares = 1, 3
	const numSessions = 8
	msg := []byte("hello, threshold ML-DSA over libp2p")

	hosts := newTestHosts(t, numShares)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	start := time.Now()
	pk, summary, err := runBatch(t, ctx, hosts, threshold, numSessions, 1, msg)
	wallClock := time.Since(start)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if len(summary.Batches) != 1 {
		t.Fatalf("len(summary.Batches) = %d, want 1", len(summary.Batches))
	}
	b := summary.Batches[0]
	if len(b.Results) != numSessions {
		t.Fatalf("len(b.Results) = %d, want %d", len(b.Results), numSessions)
	}
	if b.Accepted == 0 {
		// Not a failure on its own: with ~23% acceptance per attempt and
		// only numSessions of them, zero accepts happens legitimately often
		// enough (~12% of runs at numSessions=8) that failing the build on
		// it would just be flaky, not informative.
		t.Logf("b.Accepted = 0 out of %d attempts (expected some fraction, ~23%%, to accept - this can happen by chance)", numSessions)
	}
	t.Logf("RunBatchLocalLoopback: %d accepted, %d rejected, out of %d attempts, batch total %v",
		b.Accepted, b.Rejected, numSessions, b.Total)

	for _, r := range b.Results {
		if !r.Accepted {
			continue
		}
		if r.Sig == nil {
			t.Fatalf("session %d: Accepted but Sig is nil", r.Session)
		}
		if !mldsa44.Verify(pk, func(w io.Writer) { _, _ = w.Write(msg) }, r.Sig) {
			t.Fatalf("session %d: accepted signature failed mldsa44.Verify", r.Session)
		}
		if r.Duration <= 0 {
			t.Fatalf("session %d: Duration = %v, want > 0", r.Session, r.Duration)
		}
	}

	if b.Total <= 0 {
		t.Fatalf("b.Total = %v, want > 0", b.Total)
	}
	if b.Total > wallClock {
		t.Fatalf("b.Total = %v exceeds the test's own wall-clock time %v", b.Total, wallClock)
	}
}

// TestRunBatchRepeatsAveragesTotal checks running several repeats produces
// one BatchSummary per repeat plus their Total's mean as RunSummary.Average
// - the "average wall-clock time to complete a batch of parallel attempts"
// figure this package exists to measure.
func TestRunBatchRepeatsAveragesTotal(t *testing.T) {
	const threshold, numShares = 1, 3
	const numSessions = 4
	const repeats = 3
	msg := []byte("hello, threshold ML-DSA, repeated")

	hosts := newTestHosts(t, numShares)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	_, summary, err := runBatch(t, ctx, hosts, threshold, numSessions, repeats, msg)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if len(summary.Batches) != repeats {
		t.Fatalf("len(summary.Batches) = %d, want %d", len(summary.Batches), repeats)
	}

	var sum time.Duration
	for i, b := range summary.Batches {
		if len(b.Results) != numSessions {
			t.Fatalf("repeat %d: len(b.Results) = %d, want %d", i, len(b.Results), numSessions)
		}
		if b.Total <= 0 {
			t.Fatalf("repeat %d: Total = %v, want > 0", i, b.Total)
		}
		sum += b.Total
	}
	if want := sum / time.Duration(repeats); summary.Average != want {
		t.Fatalf("summary.Average = %v, want %v", summary.Average, want)
	}
	t.Logf("TestRunBatchRepeatsAveragesTotal: average total across %d repeats: %v", repeats, summary.Average)
}

// TestRunBatchParameterMatrix sweeps a small (threshold, numShares,
// numSessions) matrix to catch off-by-one roster/collect bugs that a
// single fixed configuration might not exercise.
func TestRunBatchParameterMatrix(t *testing.T) {
	cases := []struct {
		name                 string
		threshold, numShares int
		numSessions          int
	}{
		{"minimal-2-of-3", 1, 3, 10},
		{"threshold-3-of-7", 3, 7, 10},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte("hello, threshold ML-DSA over libp2p: " + tc.name)
			hosts := newTestHosts(t, tc.numShares)

			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			pk, summary, err := runBatch(t, ctx, hosts, tc.threshold, tc.numSessions, 1, msg)
			if err != nil {
				t.Fatalf("run failed: %v", err)
			}
			b := summary.Batches[0]
			if len(b.Results) != tc.numSessions {
				t.Fatalf("len(b.Results) = %d, want %d", len(b.Results), tc.numSessions)
			}
			for _, r := range b.Results {
				if !r.Accepted {
					continue
				}
				if !mldsa44.Verify(pk, func(w io.Writer) { _, _ = w.Write(msg) }, r.Sig) {
					t.Fatalf("session %d: accepted signature failed mldsa44.Verify", r.Session)
				}
			}
			t.Logf("%s: %d/%d accepted, batch total %v", tc.name, b.Accepted, tc.numSessions, b.Total)
		})
	}
}

// TestRunLeaderReturnsAnErrorWhenAPeerNeverJoins checks RunLeader returns a
// clear error - rather than hanging forever - when fewer than numShares-1
// peers ever join, bounded by ctx's own deadline.
func TestRunLeaderReturnsAnErrorWhenAPeerNeverJoins(t *testing.T) {
	const numShares = 3 // one peer will never join
	const threshold = 1

	hosts := newTestHosts(t, numShares)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Only party 2 joins; party 3 never does.
	go func() {
		_, _ = RunPeer(ctx, hosts[1], numShares, []peer.AddrInfo{{ID: hosts[0].ID(), Addrs: hosts[0].Addrs()}})
	}()

	start := time.Now()
	_, _, err := RunLeader(ctx, hosts[0], numShares, threshold, 1, 1, []byte("hi"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("RunLeader succeeded, want an error")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("RunLeader took %v to fail - expected close to ctx's 3s deadline", elapsed)
	}
}

// TestRunPeerRejectsTooManyConnectAddresses checks RunPeer validates its
// own derived party index (len(connect)+1) against numShares rather than
// silently accepting a nonsensical one.
func TestRunPeerRejectsTooManyConnectAddresses(t *testing.T) {
	const numShares = 3
	hosts := newTestHosts(t, numShares+1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	connect := make([]peer.AddrInfo, numShares) // -> derived self = numShares+1, out of range
	for i, h := range hosts[:numShares] {
		connect[i] = peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}
	}
	if _, err := RunPeer(ctx, hosts[numShares], numShares, connect); err == nil {
		t.Fatalf("RunPeer succeeded, want an error (too many connect addresses)")
	}
}
