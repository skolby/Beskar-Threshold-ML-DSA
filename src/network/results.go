package network

import "time"

// SessionResult is one lock-step session's outcome within one repeat, as
// observed by the leader (the only party that ever calls Finalize).
// Several sessions run in parallel within a repeat - e.g. 8 sessions at
// once, in the hope at least one accepts (~23% of individual attempts do,
// since ML-DSA rejection sampling rejects most draws) - and what matters
// is that whole group's completion time (BatchSummary.Total), not any one
// session's own latency, since in lock-step they all start and finish
// together.
type SessionResult struct {
	Session  int
	Accepted bool // true iff Finalize produced a verifying signature
	Started  time.Time
	Finished time.Time
	Duration time.Duration // Finished.Sub(Started)
	Err      error         // non-nil iff !Accepted
	Sig      []byte        // set iff Accepted
}

// BatchSummary aggregates one repeat's numSessions parallel sessions. A
// batch that aborts never produces one of these - see RunLeader - so every
// BatchSummary here represents a repeat that ran to completion.
type BatchSummary struct {
	Results []SessionResult

	// Total is the end-to-end wall-clock time of this repeat's Round1
	// through Finalize, deliberately excluding preprocessing distribution
	// and the ack wait that precede it (see RunLeader) - the number that
	// answers "how long does completing a batch of numSessions parallel
	// attempts take".
	Total time.Duration

	Accepted, Rejected int
}

// Summarize builds a BatchSummary from one repeat's results.
func Summarize(results []SessionResult) BatchSummary {
	s := BatchSummary{Results: results}
	if len(results) == 0 {
		return s
	}

	earliestStart, latestFinish := results[0].Started, results[0].Finished
	for _, r := range results {
		if r.Started.Before(earliestStart) {
			earliestStart = r.Started
		}
		if r.Finished.After(latestFinish) {
			latestFinish = r.Finished
		}
		if r.Accepted {
			s.Accepted++
		} else {
			s.Rejected++
		}
	}
	s.Total = latestFinish.Sub(earliestStart)
	return s
}

// RunSummary aggregates every repeat of one RunLeader call (see its
// repeats parameter): running the same batch several times sequentially
// and averaging each repeat's own Total is how this package measures a
// stable "time to complete a batch of parallel attempts" figure, without
// needing genuinely concurrent batches.
type RunSummary struct {
	Batches []BatchSummary
	Average time.Duration // mean of Batches[i].Total
}

// newRunSummary builds a RunSummary from every repeat's BatchSummary.
func newRunSummary(batches []BatchSummary) RunSummary {
	s := RunSummary{Batches: batches}
	if len(batches) == 0 {
		return s
	}
	var sum time.Duration
	for _, b := range batches {
		sum += b.Total
	}
	s.Average = sum / time.Duration(len(batches))
	return s
}
