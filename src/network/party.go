package network

// party.go is the whole per-party state machine, and the two entry points
// that drive it: RunLeader (party 1) and RunPeer (every other party).
//
// Connections are set up from the command line, not discovered: every
// party is told the dialable addresses of every already-started party (in
// join order) and dials them directly, announcing its own party index -
// len(that address list)+1 - with one MsgHello. There's no leader-relayed
// join protocol and no address gossiping: by the time the last party
// starts and dials everyone, every pair of parties has a connection (each
// later party dialed each earlier one), and every party either already
// knew an earlier party's index (its position in its own -connect list)
// or learns a later party's index from that party's MsgHello. See
// cmd/tmldsa-network for the CLI that drives this.
//
// Every parallel session in one repeat runs in lock-step (runSessions):
// this party's message for every session, for one round, is computed
// before any of them are sent, and every one of them is sent before this
// party waits for anything back. Round1/Round2 are all-to-all; Round3
// goes to the leader only, who alone finalizes. A genuine
// Round1/Round2/Round3 error at any party aborts the whole run - not just
// the one repeat or session - since it means some party is broken and
// can't be trusted for anything else in this run either.

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	tmprotocol "t-mldsa/src/protocol"
)

// Party is one process's live state: its libp2p host, its own party index,
// the roster it has learned so far, and everything runSessions needs to
// run a batch of lock-step sessions with it.
type Party struct {
	Host     host.Host
	Self     int // 1-indexed; 1 is always the leader
	N        int // total number of parties
	IsLeader bool

	mu     sync.Mutex
	roster map[int]peer.ID

	fullRoster     chan struct{}
	fullRosterOnce sync.Once

	inbox chan Envelope

	pendingMu sync.Mutex
	pending   []Envelope

	doneCh   chan struct{}
	doneOnce sync.Once

	ctx    context.Context
	cancel context.CancelCauseFunc
}

func newParty(ctx context.Context, h host.Host, self, n int, isLeader bool) *Party {
	pctx, cancel := context.WithCancelCause(ctx)
	p := &Party{
		Host:       h,
		Self:       self,
		N:          n,
		IsLeader:   isLeader,
		roster:     make(map[int]peer.ID, n),
		fullRoster: make(chan struct{}),
		inbox:      make(chan Envelope, n*4),
		doneCh:     make(chan struct{}),
		ctx:        pctx,
		cancel:     cancel,
	}
	h.SetStreamHandler(StreamProtocolID, p.handleStream)
	p.recordRoster(self, h.ID()) // a party always knows its own address
	log.Printf("network: party %d/%d: started (leader=%v)", self, n, isLeader)
	return p
}

// Context returns this party's run context - cancelled once the run
// aborts, with context.Cause naming the fault.
func (p *Party) Context() context.Context { return p.ctx }

// Finished reports when the leader has told this party every repeat is
// done (only ever fires at a non-leader party; the leader knows it's done
// simply by RunLeader returning).
func (p *Party) Finished() <-chan struct{} { return p.doneCh }

// handleStream reads the one Envelope a stream carries and routes it:
// MsgHello updates the roster directly, MsgAbort triggers the run's
// cancellation directly, everything else is handed to whichever call is
// currently waiting for it (collect, below).
func (p *Party) handleStream(s network.Stream) {
	env, err := readEnvelope(s)
	from := s.Conn().RemotePeer()
	s.Close()
	if err != nil {
		log.Printf("network: party %d: dropping unreadable stream from %s: %v", p.Self, from, err)
		return // malformed/unreadable - nothing more to do with this stream
	}
	log.Printf("network: party %d: received %s from party %d (%s)", p.Self, env.Type, env.From, from)

	switch env.Type {
	case MsgHello:
		p.recordRoster(env.From, from)
	case MsgAbort:
		p.triggerAbort(fmt.Errorf("party %d reported: %s", env.From, env.Reason))
	default:
		select {
		case p.inbox <- env:
		case <-p.ctx.Done():
		}
	}
}

// recordRoster registers idx as reachable at id, the first time only, and
// closes fullRoster once every one of the N parties is known.
func (p *Party) recordRoster(idx int, id peer.ID) {
	p.mu.Lock()
	_, exists := p.roster[idx]
	if !exists {
		p.roster[idx] = id
	}
	known := len(p.roster)
	full := known == p.N
	p.mu.Unlock()
	if !exists {
		log.Printf("network: party %d: roster now knows party %d (%s) - %d/%d known", p.Self, idx, id, known, p.N)
	}
	if full {
		p.fullRosterOnce.Do(func() {
			log.Printf("network: party %d: full roster reached (%d parties)", p.Self, p.N)
			close(p.fullRoster)
		})
	}
}

func (p *Party) peerFor(idx int) (peer.ID, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, ok := p.roster[idx]
	return id, ok
}

// waitFullRoster blocks until every one of the N parties is known. Every
// party needs this, not just the leader: Round1/Round2 broadcast to
// everyone, so a party with an incomplete roster can't yet address its
// own contribution to whoever it's still missing.
func (p *Party) waitFullRoster() error {
	select {
	case <-p.fullRoster:
		return nil
	case <-p.ctx.Done():
		return context.Cause(p.ctx)
	}
}

// triggerAbort cancels this run, recording err as the cause, and - the
// first time only - tells every other known party to do the same.
// Idempotent: context.CancelCauseFunc only keeps the first call's cause,
// and the already check below stops a duplicate local fault or a racing
// remote MsgAbort from re-broadcasting.
func (p *Party) triggerAbort(err error) {
	already := p.ctx.Err() != nil
	if !already {
		log.Printf("network: party %d: aborting run: %v", p.Self, err)
	}
	p.cancel(err)
	if already {
		return
	}

	p.mu.Lock()
	targets := make([]peer.ID, 0, len(p.roster))
	for idx, id := range p.roster {
		if idx != p.Self {
			targets = append(targets, id)
		}
	}
	p.mu.Unlock()

	env := Envelope{Type: MsgAbort, From: p.Self, Reason: err.Error()}
	for _, id := range targets {
		// context.Background(), deliberately: p.ctx is already cancelled by
		// the trigger above, which would make every send below fail
		// immediately - defeating the point of telling everyone else.
		go func(id peer.ID) { _ = sendEnvelope(context.Background(), p.Host, id, env) }(id)
	}
}

func (p *Party) markDone() { p.doneOnce.Do(func() { close(p.doneCh) }) }

// broadcast sends env (with From filled in) to every other known party,
// fire-and-forget: an individual send failing doesn't block or fault the
// sender - the intended recipient's own collect simply keeps waiting
// (until the run's context ends), which is what surfaces a truly
// unreachable peer, rather than this function guessing at a retry policy.
func (p *Party) broadcast(env Envelope) {
	env.From = p.Self
	p.mu.Lock()
	targets := make([]peer.ID, 0, len(p.roster))
	for idx, id := range p.roster {
		if idx != p.Self {
			targets = append(targets, id)
		}
	}
	p.mu.Unlock()
	log.Printf("network: party %d: broadcasting %s to %d part(y/ies)", p.Self, env.Type, len(targets))
	for _, id := range targets {
		go func(id peer.ID) { _ = sendEnvelope(p.ctx, p.Host, id, env) }(id)
	}
}

// sendTo sends env (with From filled in) to one other party by index.
func (p *Party) sendTo(idx int, env Envelope) error {
	id, ok := p.peerFor(idx)
	if !ok {
		return fmt.Errorf("network: no known address for party %d", idx)
	}
	env.From = p.Self
	log.Printf("network: party %d: sending %s to party %d", p.Self, env.Type, idx)
	return sendEnvelope(p.ctx, p.Host, id, env)
}

// collect blocks until one Envelope of msgType has arrived from every
// party index in from, keyed by sender. An Envelope that doesn't match
// (e.g. a message meant for a different collect call, delivered while
// this one is waiting) is stashed in pending for whichever later call it
// actually belongs to - safe because this package only ever has one
// collect call outstanding at a time (everything is strictly lock-step).
func (p *Party) collect(msgType MsgType, from []int) (map[int][][]byte, error) {
	want := make(map[int]bool, len(from))
	for _, idx := range from {
		want[idx] = true
	}
	got := make(map[int][][]byte, len(from))

	p.pendingMu.Lock()
	kept := p.pending[:0]
	for _, env := range p.pending {
		if env.Type == msgType && want[env.From] {
			got[env.From] = env.Payloads
			delete(want, env.From)
		} else {
			kept = append(kept, env)
		}
	}
	p.pending = kept
	p.pendingMu.Unlock()

	if len(want) > 0 {
		log.Printf("network: party %d: waiting for %s from %v (already have %d/%d)", p.Self, msgType, from, len(from)-len(want), len(from))
	}

	for len(want) > 0 {
		select {
		case <-p.ctx.Done():
			return nil, context.Cause(p.ctx)
		case env := <-p.inbox:
			if env.Type == msgType && want[env.From] {
				got[env.From] = env.Payloads
				delete(want, env.From)
				continue
			}
			p.pendingMu.Lock()
			p.pending = append(p.pending, env)
			p.pendingMu.Unlock()
		}
	}
	log.Printf("network: party %d: collected %s from every expected party", p.Self, msgType)
	return got, nil
}

// otherIndices returns every party index 1..n except self.
func otherIndices(self, n int) []int {
	out := make([]int, 0, n-1)
	for i := 1; i <= n; i++ {
		if i != self {
			out = append(out, i)
		}
	}
	return out
}

// merge folds this party's own per-session payloads and every other
// party's collected bundle (assumed, like mine, to have one entry per
// session) into one party-index-ordered table per session:
// table[session][idx-1] is party idx's payload for that session.
func merge(myIdx int, mine [][]byte, others map[int][][]byte, n int) [][][]byte {
	table := make([][][]byte, len(mine))
	for i := range table {
		table[i] = make([][]byte, n)
		table[i][myIdx] = mine[i]
	}
	for idx, payloads := range others {
		for i, m := range payloads {
			table[i][idx-1] = m
		}
	}
	return table
}

// runSessions drives one repeat's Round1 -> Round2 -> Round3 ->
// (Finalize, leader only) for every session in preSign, in lock-step: see
// the package doc comment. Returns nil results for a non-leader party - it
// has nothing to report, since only the leader ever calls Finalize.
func (p *Party) runSessions(key tmprotocol.KeyState, preSign []tmprotocol.PreprocessingState, msg []byte) ([]SessionResult, error) {
	numSessions := len(preSign)
	n := key.NumShares()
	myIdx := key.PartyID() - 1
	others := otherIndices(p.Self, n)
	started := time.Now()

	log.Printf("network: party %d: round1: computing %d session(s)", p.Self, numSessions)
	r1States := make([]tmprotocol.Round1State, numSessions)
	r1Payloads := make([][]byte, numSessions)
	for i, ps := range preSign {
		err, state, m := tmprotocol.Round1Encoded(key, ps, msg)
		if err != nil {
			return nil, p.fault(1, err)
		}
		r1States[i], r1Payloads[i] = state, m
	}
	p.broadcast(Envelope{Type: MsgRound1, Payloads: r1Payloads})
	r1FromOthers, err := p.collect(MsgRound1, others)
	if err != nil {
		return nil, err
	}
	r1All := merge(myIdx, r1Payloads, r1FromOthers, n)

	log.Printf("network: party %d: round2: computing %d session(s)", p.Self, numSessions)
	r2States := make([]tmprotocol.Round2State, numSessions)
	r2Payloads := make([][]byte, numSessions)
	for i, ps := range preSign {
		err, state, m := tmprotocol.Round2Encoded(key, ps, r1States[i], r1All[i])
		if err != nil {
			return nil, p.fault(2, err)
		}
		r2States[i], r2Payloads[i] = state, m
	}
	p.broadcast(Envelope{Type: MsgRound2, Payloads: r2Payloads})
	r2FromOthers, err := p.collect(MsgRound2, others)
	if err != nil {
		return nil, err
	}
	r2All := merge(myIdx, r2Payloads, r2FromOthers, n)

	log.Printf("network: party %d: round3: computing %d session(s)", p.Self, numSessions)
	r3States := make([]tmprotocol.Round3State, numSessions)
	r3Payloads := make([][]byte, numSessions)
	for i, ps := range preSign {
		err, state, m := tmprotocol.Round3Encoded(key, ps, r2States[i], r2All[i])
		if err != nil {
			return nil, p.fault(3, err)
		}
		r3States[i], r3Payloads[i] = state, m
	}

	if !p.IsLeader {
		if err := p.sendTo(1, Envelope{Type: MsgRound3, Payloads: r3Payloads}); err != nil {
			return nil, fmt.Errorf("network: sending Round3 to leader: %w", err)
		}
		log.Printf("network: party %d: round3 sent to leader, this repeat's work is done", p.Self)
		return nil, nil
	}

	r3FromPeers, err := p.collect(MsgRound3, others)
	if err != nil {
		return nil, err
	}
	r3All := merge(myIdx, r3Payloads, r3FromPeers, n)

	log.Printf("network: leader: finalizing %d session(s)", numSessions)
	results := make([]SessionResult, numSessions)
	for i := range preSign {
		err, sig := tmprotocol.FinalizeEncoded(key, r3States[i], r3All[i])
		finished := time.Now()
		results[i] = SessionResult{Session: i, Started: started, Finished: finished, Duration: finished.Sub(started)}
		if err != nil {
			results[i].Err = err // expected outcome of a rejected draw - not a fault, no abort
		} else {
			results[i].Accepted = true
			results[i].Sig = sig
		}
	}
	return results, nil
}

// fault turns a genuine Round1/Round2/Round3 error into this run's abort
// reason, triggers it, and returns it for the caller to propagate.
func (p *Party) fault(round int, err error) error {
	wrapped := fmt.Errorf("round%d: %w", round, err)
	p.triggerAbort(wrapped)
	return wrapped
}

// RunLeader runs this process as party 1 of numShares: it waits for every
// other party to connect and announce itself, deals keys once, then for
// each of repeats: deals fresh preprocessing for numSessions parallel
// sessions all signing msg, distributes it and waits for every peer to
// acknowledge it (not timed - see BatchSummary.Total), then runs every
// session's Round1->Round2->Round3->Finalize in lock-step (timed). Once
// every repeat is done, tells every peer so and returns.
func RunLeader(ctx context.Context, h host.Host, numShares, threshold, numSessions, repeats int, msg []byte) (*mldsa44.PublicKey, RunSummary, error) {
	if numShares < 3 {
		return nil, RunSummary{}, fmt.Errorf("network: need at least 3 parties, got %d", numShares)
	}
	if numSessions < 1 {
		return nil, RunSummary{}, fmt.Errorf("network: numSessions must be >= 1, got %d", numSessions)
	}
	if repeats < 1 {
		return nil, RunSummary{}, fmt.Errorf("network: repeats must be >= 1, got %d", repeats)
	}

	p := newParty(ctx, h, 1, numShares, true)
	log.Printf("network: leader: waiting for all %d parties to join", numShares)
	if err := p.waitFullRoster(); err != nil {
		return nil, RunSummary{}, fmt.Errorf("network: waiting for every party to join: %w", err)
	}
	log.Printf("network: leader: all parties joined, dealing keys (threshold=%d, numShares=%d)", threshold, numShares)

	pk, keys, err := tmprotocol.DealKeys(threshold, numShares)
	if err != nil {
		return nil, RunSummary{}, fmt.Errorf("network: DealKeys: %w", err)
	}
	log.Printf("network: leader: keys dealt")

	var batches []BatchSummary
	for r := 0; r < repeats; r++ {
		log.Printf("network: leader: repeat %d/%d: dealing preprocessing for %d session(s)", r+1, repeats, numSessions)
		preSign := make([][]tmprotocol.PreprocessingState, numShares)
		for s := 0; s < numSessions; s++ {
			perParty, _, _, err := tmprotocol.DealPreSig(threshold, numShares, pk)
			if err != nil {
				return pk, newRunSummary(batches), fmt.Errorf("network: DealPreSig: %w", err)
			}
			for i, ps := range perParty {
				preSign[i] = append(preSign[i], ps)
			}
		}

		for i := 2; i <= numShares; i++ {
			bundle := PreprocessingBundle{Key: keys[i-1], Sessions: preSign[i-1]}
			payload, err := encodeBundle(bundle)
			if err != nil {
				return pk, newRunSummary(batches), fmt.Errorf("network: encoding bundle for party %d: %w", i, err)
			}
			if err := p.sendTo(i, Envelope{Type: MsgPreprocessing, Payload: payload}); err != nil {
				return pk, newRunSummary(batches), fmt.Errorf("network: distributing preprocessing to party %d: %w", i, err)
			}
		}
		log.Printf("network: leader: repeat %d/%d: preprocessing sent, waiting for acks", r+1, repeats)
		if _, err := p.collect(MsgAck, otherIndices(1, numShares)); err != nil {
			return pk, newRunSummary(batches), fmt.Errorf("network: waiting for preprocessing acks: %w", err)
		}

		log.Printf("network: leader: repeat %d/%d: all acked, starting sessions", r+1, repeats)
		p.broadcast(Envelope{Type: MsgStart, Payload: msg})
		results, err := p.runSessions(keys[0], preSign[0], msg)
		if err != nil {
			return pk, newRunSummary(batches), err
		}
		batch := Summarize(results)
		log.Printf("network: leader: repeat %d/%d: done - %d accepted, %d rejected, took %v", r+1, repeats, batch.Accepted, batch.Rejected, batch.Total)
		batches = append(batches, batch)
	}

	log.Printf("network: leader: all %d repeat(s) done, telling every party", repeats)
	p.broadcast(Envelope{Type: MsgDone})
	return pk, newRunSummary(batches), nil
}

// RunPeer runs this process as one non-leader party: self is derived as
// len(connect)+1, and connect must be the dialable address of every
// already-started party, in join order (party 1 first) - see the package
// doc comment. It dials and announces itself to each, then returns a live
// Party that reacts to the leader from then on (see react): callers that
// want to know when this party's run ends should watch the returned
// Party's Finished() (normal completion) and Context() (abort).
func RunPeer(ctx context.Context, h host.Host, numShares int, connect []peer.AddrInfo) (*Party, error) {
	self := len(connect) + 1
	if self < 2 || self > numShares {
		return nil, fmt.Errorf("network: got %d already-started address(es), expected between 1 and %d for numShares=%d", len(connect), numShares-1, numShares)
	}

	p := newParty(ctx, h, self, numShares, false)

	for i, addr := range connect {
		idx := i + 1
		log.Printf("network: party %d: connecting to party %d (%s)", self, idx, addr.ID)
		if err := h.Connect(ctx, addr); err != nil {
			return nil, fmt.Errorf("network: connecting to party %d: %w", idx, err)
		}
		p.recordRoster(idx, addr.ID)
		if err := helloWithRetry(ctx, h, addr.ID, self); err != nil {
			return nil, fmt.Errorf("network: announcing to party %d: %w", idx, err)
		}
		log.Printf("network: party %d: connected and announced to party %d", self, idx)
	}

	go p.react()
	return p, nil
}

// helloWithRetry sends a MsgHello to id, retrying a few times a beat
// apart: id's own process might only just be starting up (concurrent
// startup, e.g. in a test harness that starts every party at once) and
// not have its stream handler registered yet, which fails protocol
// negotiation transiently rather than because id is actually unreachable.
func helloWithRetry(ctx context.Context, h host.Host, id peer.ID, self int) error {
	env := Envelope{Type: MsgHello, From: self}
	var lastErr error
	for {
		lastErr = sendEnvelope(ctx, h, id, env)
		if lastErr == nil {
			return nil
		}
		select {
		case <-time.After(20 * time.Millisecond):
		case <-ctx.Done():
			return lastErr
		}
	}
}

// react is a joined peer's whole reactive loop: apply whatever
// preprocessing the leader distributes (acking it), run every repeat's
// lock-step sessions the leader starts via MsgStart, and return once the
// leader reports the run done, the run aborts, or its context ends.
func (p *Party) react() {
	log.Printf("network: party %d: waiting for full roster before reacting", p.Self)
	if err := p.waitFullRoster(); err != nil {
		log.Printf("network: party %d: giving up waiting for roster: %v", p.Self, err)
		return
	}
	log.Printf("network: party %d: entering reactive loop", p.Self)

	var key tmprotocol.KeyState
	var preSign []tmprotocol.PreprocessingState
	for {
		select {
		case <-p.ctx.Done():
			return
		case env := <-p.inbox:
			switch env.Type {
			case MsgPreprocessing:
				bundle, err := decodeBundle(env.Payload)
				if err != nil {
					log.Printf("network: party %d: failed to decode preprocessing bundle: %v", p.Self, err)
					continue // can't even ack; the leader's ack wait will surface this
				}
				key, preSign = bundle.Key, bundle.Sessions
				log.Printf("network: party %d: applied preprocessing for %d session(s), acking", p.Self, len(preSign))
				_ = p.sendTo(1, Envelope{Type: MsgAck})
			case MsgStart:
				log.Printf("network: party %d: starting sessions for this repeat", p.Self)
				if _, err := p.runSessions(key, preSign, env.Payload); err != nil {
					log.Printf("network: party %d: run aborted: %v", p.Self, err)
					return
				}
			case MsgDone:
				log.Printf("network: party %d: leader reported the run done", p.Self)
				p.markDone()
				return
			default:
				// A Round1/Round2/Round3 (or Ack) message can legitimately
				// race ahead of the Start/Preprocessing message that would
				// otherwise hand it off to a collect() call: broadcast/sendTo
				// open one independent stream per message, so delivery order
				// across different messages isn't guaranteed even when this
				// party sent them (or the sender sent them) in a fixed
				// order. Stash it exactly like collect() does for a
				// type/sender it isn't currently waiting on, so the collect()
				// call that does want it (inside the runSessions this
				// MsgStart is about to trigger) still finds it - instead of
				// silently dropping it here and hanging forever waiting for
				// a message that already arrived.
				log.Printf("network: party %d: stashing early %s from party %d", p.Self, env.Type, env.From)
				p.pendingMu.Lock()
				p.pending = append(p.pending, env)
				p.pendingMu.Unlock()
			}
		}
	}
}
