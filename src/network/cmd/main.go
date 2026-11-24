// Command tmldsa-network runs one party of the distributed threshold
// ML-DSA protocol (package network) as its own, independent OS process.
// Run one leader (party 1, the process with no -connect) and numShares-1
// peer processes - on the same machine or different ones - to sign a
// message together. See src/network/README.md for full manual-run
// instructions.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"t-mldsa/src/circl-mldsa/sign/mldsa/mldsa44"
	"t-mldsa/src/network"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tmldsa-network:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen    = flag.String("listen", "/ip4/0.0.0.0/tcp/0", "multiaddr to listen on")
		connect   = flag.String("connect", "", "comma-separated multiaddr of every already-started party, in join order (empty = this is party 1, the leader)")
		numShares = flag.Int("n", 0, "total number of parties (required, agreed on beforehand by everyone)")
		threshold = flag.Int("t", 0, "leader only: Shamir threshold (required for party 1)")
		sessions  = flag.Int("sessions", 1, "leader only: number of parallel signing sessions per repeat")
		repeats   = flag.Int("repeats", 1, "leader only: number of times to repeat the batch, to average its total time")
		message   = flag.String("message", "hello, threshold ML-DSA", "leader only: the message every session signs")
		timeout   = flag.Duration("timeout", 10*time.Minute, "overall process timeout")
	)
	flag.Parse()

	if *numShares < 2 {
		return fmt.Errorf("-n must be >= 2, got %d", *numShares)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	h, err := network.NewHost(*listen)
	if err != nil {
		return fmt.Errorf("creating host: %w", err)
	}
	defer h.Close()

	addrs, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: h.ID(), Addrs: h.Addrs()})
	if err != nil {
		return fmt.Errorf("resolving this host's own dialable addresses: %w", err)
	}

	if *connect == "" {
		if *threshold <= 0 {
			return fmt.Errorf("-t is required and must be > 0 for party 1 (the leader)")
		}
		log.Printf("party 1 of %d (leader), listening at:", *numShares)
		for _, a := range addrs {
			log.Printf("  %s", a)
		}
		if *numShares > 1 {
			log.Printf("start party 2 with:")
			log.Printf("  %s -n=%d -t=%d -listen=/ip4/0.0.0.0/tcp/0 -connect=%s", os.Args[0], *numShares, *threshold, addrs[0])
		}
		return runLeader(ctx, h, *numShares, *threshold, *sessions, *repeats, *message)
	}

	connectAddrs, err := parseConnect(*connect)
	if err != nil {
		return fmt.Errorf("parsing -connect: %w", err)
	}
	self := len(connectAddrs) + 1
	log.Printf("party %d of %d, listening at:", self, *numShares)
	for _, a := range addrs {
		log.Printf("  %s", a)
	}
	if self < *numShares {
		log.Printf("start party %d with:", self+1)
		log.Printf("  %s -n=%d -t=%d -listen=/ip4/0.0.0.0/tcp/0 -connect=%s,%s", os.Args[0], *numShares, *threshold, *connect, addrs[0])
	}
	return runPeer(ctx, h, *numShares, connectAddrs)
}

// parseConnect parses -connect's comma-separated multiaddr list, each
// expected to include a /p2p/<peer ID> component (as printed on startup).
func parseConnect(s string) ([]peer.AddrInfo, error) {
	parts := strings.Split(s, ",")
	out := make([]peer.AddrInfo, len(parts))
	for i, part := range parts {
		info, err := peer.AddrInfoFromString(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("address %d (%q): %w", i+1, part, err)
		}
		out[i] = *info
	}
	return out, nil
}

func runLeader(ctx context.Context, h host.Host, numShares, threshold, sessions, repeats int, message string) error {
	pk, summary, err := network.RunLeader(ctx, h, numShares, threshold, sessions, repeats, []byte(message))
	if err != nil {
		return fmt.Errorf("running batch: %w", err)
	}

	var pkBuf [mldsa44.PublicKeySize]byte
	pk.Pack(&pkBuf)
	log.Printf("leader: public key: %x", pkBuf)
	for i, b := range summary.Batches {
		log.Printf("leader: repeat %d: %d accepted, %d rejected, out of %d session(s), total %v", i, b.Accepted, b.Rejected, len(b.Results), b.Total)
	}
	log.Printf("leader: average total across %d repeat(s): %v", len(summary.Batches), summary.Average)
	return nil
}

func runPeer(ctx context.Context, h host.Host, numShares int, connect []peer.AddrInfo) error {
	p, err := network.RunPeer(ctx, h, numShares, connect)
	if err != nil {
		return fmt.Errorf("joining: %w", err)
	}
	log.Printf("peer: joined - reacting to the leader's messages from here on (Ctrl+C to stop)")

	select {
	case <-p.Finished():
		log.Printf("peer: leader reported the run done")
	case <-p.Context().Done():
		if cause := context.Cause(p.Context()); cause != nil {
			log.Printf("peer: run aborted: %v", cause)
		}
	case <-ctx.Done():
		log.Printf("peer: stopping (%v)", ctx.Err())
	}
	return nil
}
