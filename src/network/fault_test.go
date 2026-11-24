package network

// fault_test.go exercises the failure paths RunLeader/RunPeer's shared
// abort logic (party.go) needs to get right: any party's genuine
// Round1/Round2/Round3 error aborts the whole run, a party that can't
// otherwise make progress doesn't hang forever, and neither a stray
// message nor a stray abort crashes anything.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	tmprotocol "t-mldsa/src/protocol"
)

// setupHonestParties deals real keys/preprocessing for one session across
// numShares parties and returns one *Party per host, already fully
// connected to (and aware of) every other - the same end state RunPeer's
// dial+hello dance reaches, but built directly since these tests need to
// call runSessions themselves (network_test.go already covers the real
// RunLeader/RunPeer path end to end).
func setupHonestParties(t *testing.T, ctx context.Context, numShares int) ([]*Party, []tmprotocol.KeyState, []tmprotocol.PreprocessingState) {
	t.Helper()
	const threshold = 1

	hosts := make([]host.Host, numShares)
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

	pk, keys, err := tmprotocol.DealKeys(threshold, numShares)
	if err != nil {
		t.Fatalf("DealKeys failed: %v", err)
	}
	preSign, _, _, err := tmprotocol.DealPreSig(threshold, numShares, pk)
	if err != nil {
		t.Fatalf("DealPreSig failed: %v", err)
	}

	parties := make([]*Party, numShares)
	for i, h := range hosts {
		parties[i] = newParty(ctx, h, i+1, numShares, i == 0)
	}
	for i, p := range parties {
		for j, h := range hosts {
			if i == j {
				continue
			}
			if err := p.Host.Connect(ctx, peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()}); err != nil {
				t.Fatalf("connecting party %d to party %d: %v", i+1, j+1, err)
			}
			p.recordRoster(j+1, h.ID())
		}
	}
	return parties, keys, preSign
}

// TestFaultCorruptedRound1TriggersAbort checks that a garbage (not a
// valid packed Round1Message) payload, sent as one party's Round1
// contribution, is treated as a genuine reconstruction fault: every other
// party's run aborts within a bounded time.
func TestFaultCorruptedRound1TriggersAbort(t *testing.T) {
	const numShares = 3
	msg := []byte("hello, threshold ML-DSA")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	parties, keys, preSign := setupHonestParties(t, ctx, numShares)
	honest := parties[:2] // parties 1 and 2 run real sessions

	var wg sync.WaitGroup
	for i, p := range honest {
		wg.Add(1)
		go func(i int, p *Party) {
			defer wg.Done()
			_, _ = p.runSessions(keys[i], []tmprotocol.PreprocessingState{preSign[i]}, msg)
		}(i, p)
	}

	// Party 3 never runs its own session - instead it sends every honest
	// party a corrupted Round1 contribution directly.
	faultyHost := parties[2].Host
	corrupt := Envelope{Type: MsgRound1, From: 3, Payloads: [][]byte{[]byte("not a valid packed Round1Message")}}
	for _, p := range honest {
		if err := sendEnvelope(ctx, faultyHost, p.Host.ID(), corrupt); err != nil {
			t.Fatalf("sending corrupted Round1: %v", err)
		}
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("runSessions did not return on either honest party within the deadline")
	}

	for i, p := range honest {
		if cause := context.Cause(p.Context()); cause == nil {
			t.Fatalf("party %d: run did not abort (nil cause)", i+1)
		}
	}
}

// TestFaultUnresponsivePartyTimesOutCleanly checks that when one party
// never sends anything at all (dropped, not corrupted), the remaining
// parties don't hang forever: with a bounded parent context, their
// sessions end via that context's own deadline rather than blocking
// indefinitely. This package has no active liveness/dropout detection -
// the bounded context is the only backstop, and this test is what proves
// that backstop actually works.
func TestFaultUnresponsivePartyTimesOutCleanly(t *testing.T) {
	const numShares = 3
	msg := []byte("hello, threshold ML-DSA")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	parties, keys, preSign := setupHonestParties(t, ctx, numShares)
	honest := parties[:2] // party 3 never sends anything

	var wg sync.WaitGroup
	errs := make([]error, len(honest))
	for i, p := range honest {
		wg.Add(1)
		go func(i int, p *Party) {
			defer wg.Done()
			_, errs[i] = p.runSessions(keys[i], []tmprotocol.PreprocessingState{preSign[i]}, msg)
		}(i, p)
	}

	start := time.Now()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("runSessions never unblocked - collect hung past the parent context's own deadline")
	}
	elapsed := time.Since(start)

	for i, p := range honest {
		// Expected: the parent ctx's own deadline, not a raised fault
		// (nothing ever went wrong from the protocol's point of view -
		// party 3 just never spoke).
		if cause := context.Cause(p.Context()); cause != context.DeadlineExceeded {
			t.Fatalf("party %d: unexpected abort cause: %v", i+1, cause)
		}
		if errs[i] == nil {
			t.Fatalf("party %d: runSessions returned a nil error, want the deadline error", i+1)
		}
	}
	if elapsed > 8*time.Second {
		t.Fatalf("took %v to notice the parent context ended - expected close to its 3s deadline", elapsed)
	}
}

// TestCollectBuffersUnexpectedEnvelopes checks an Envelope that arrives
// before any collect call is waiting for it (e.g. a faster party's
// message racing ahead) is buffered in pending and handed to the call it
// actually belongs to, rather than dropped.
func TestCollectBuffersUnexpectedEnvelopes(t *testing.T) {
	const numShares = 3
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	parties, _, _ := setupHonestParties(t, ctx, numShares)
	p := parties[0]

	// Equivalent to this having arrived over the wire via handleStream's
	// default case, before anyone called collect for it.
	p.inbox <- Envelope{Type: MsgRound2, From: 2, Payloads: [][]byte{[]byte("session 0 round2")}}

	got, err := p.collect(MsgRound2, []int{2})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(got[2]) != 1 || string(got[2][0]) != "session 0 round2" {
		t.Fatalf("collect returned %+v, want the buffered envelope", got)
	}
}

// TestReactBuffersEarlyRoundEnvelopes checks that a Round1/Round2/Round3
// envelope delivered to a peer's inbox before the MsgStart/MsgPreprocessing
// that would otherwise hand it off to a collect() call is buffered in
// pending, not silently dropped: broadcast/sendTo open one independent
// stream per message, so a round message can race ahead of whatever
// react's own top-level loop is currently waiting on - regression test for
// a bug where react's dispatch switch had no default case and threw such
// an envelope away instead of stashing it like collect() does.
func TestReactBuffersEarlyRoundEnvelopes(t *testing.T) {
	const numShares = 3
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	parties, _, _ := setupHonestParties(t, ctx, numShares)
	p := parties[1] // a real peer (react only ever runs on non-leader parties)

	// Equivalent to this Round1 contribution having arrived over the wire,
	// via handleStream's default case, before this party has processed the
	// MsgStart that would trigger runSessions (and its own collect call) to
	// consume it.
	early := Envelope{Type: MsgRound1, From: 3, Payloads: [][]byte{[]byte("session 0 round1")}}
	p.inbox <- early
	// Queued right after: MsgDone is one react handles directly and returns
	// on, giving a deterministic point by which "early" must already have
	// been dequeued (p.inbox is FIFO with react as its one reader) -
	// without a sleep/poll racing react's own goroutine.
	p.inbox <- Envelope{Type: MsgDone}

	go p.react()

	select {
	case <-p.Finished():
	case <-time.After(5 * time.Second):
		t.Fatalf("react never processed MsgDone")
	}

	p.pendingMu.Lock()
	pending := p.pending
	p.pendingMu.Unlock()
	if len(pending) != 1 || pending[0].Type != MsgRound1 || pending[0].From != 3 {
		t.Fatalf("pending = %+v, want the buffered early Round1 envelope", pending)
	}

	// The real-world path this feeds: whichever collect call actually wants
	// it (inside the runSessions the real MsgStart would have triggered)
	// finds it immediately instead of hanging forever waiting for a message
	// that already arrived.
	got, err := p.collect(MsgRound1, []int{3})
	if err != nil {
		t.Fatalf("collect failed: %v", err)
	}
	if len(got[3]) != 1 || string(got[3][0]) != "session 0 round1" {
		t.Fatalf("collect returned %+v, want the buffered envelope", got)
	}
}

// TestAbortTriggersImmediately checks a received MsgAbort cancels the
// recipient's run directly from handleStream - it doesn't need anything
// else (e.g. a collect call) to be waiting on it first.
func TestAbortTriggersImmediately(t *testing.T) {
	const numShares = 3
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	parties, _, _ := setupHonestParties(t, ctx, numShares)
	p := parties[0]
	faultyHost := parties[2].Host

	env := Envelope{Type: MsgAbort, From: 3, Reason: "injected for test"}
	if err := sendEnvelope(ctx, faultyHost, p.Host.ID(), env); err != nil {
		t.Fatalf("sending abort: %v", err)
	}

	select {
	case <-p.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("party did not abort after receiving MsgAbort")
	}
}
