// Package network runs the threshold ML-DSA protocol (package protocol)
// distributed over libp2p, purely so its behavior can be timed over a real
// network - it isn't meant to be production-ready network code. One party
// (party 1) deals keys/preprocessing and drives numSessions parallel
// signing sessions per repeat, in lock-step, through Start -> Round1 ->
// Round2 -> Round3 -> Finalize (leader-only); see party.go.
package network

// wire.go: the one envelope every libp2p stream carries, gob-encoded over
// one shared protocol ID, one stream per message - plus libp2p host setup
// and the low-level send/receive helpers built on it. One protocol ID (not
// one per message type) keeps handler registration to a single
// SetStreamHandler call; gob needs no schema and encodes []byte directly
// (no base64 blowup like JSON), appropriate since the real wire-format
// work already happened in protocol's hand-rolled *Encoded codecs - this
// envelope is just metadata plus an opaque blob.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/gob"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	p2pprotocol "github.com/libp2p/go-libp2p/core/protocol"

	tmprotocol "t-mldsa/src/protocol"
)

// StreamProtocolID is the libp2p protocol every Envelope is sent under.
const StreamProtocolID p2pprotocol.ID = "/t-mldsa/1.0.0"

// MsgType identifies what an Envelope carries.
type MsgType uint8

const (
	MsgHello         MsgType = iota // dialer -> dialee, once, right after connecting: announces From
	MsgPreprocessing                // leader -> peer, once per repeat: gob-encoded PreprocessingBundle
	MsgAck                          // peer -> leader: preprocessing received & applied
	MsgStart                        // leader -> peer: begin this repeat; Payload is the message to sign
	MsgRound1                       // all-to-all: Payloads[i] is Round1Encoded's output for session i
	MsgRound2                       // all-to-all: Payloads[i] is Round2Encoded's output for session i
	MsgRound3                       // peer -> leader only: Payloads[i] is Round3Encoded's output for session i
	MsgDone                         // leader -> peer: every repeat is finished
	MsgAbort                        // any -> every other known party: a genuine reconstruction fault
)

func (t MsgType) String() string {
	switch t {
	case MsgHello:
		return "Hello"
	case MsgPreprocessing:
		return "Preprocessing"
	case MsgAck:
		return "Ack"
	case MsgStart:
		return "Start"
	case MsgRound1:
		return "Round1"
	case MsgRound2:
		return "Round2"
	case MsgRound3:
		return "Round3"
	case MsgDone:
		return "Done"
	case MsgAbort:
		return "Abort"
	default:
		return fmt.Sprintf("MsgType(%d)", uint8(t))
	}
}

// Envelope is the single message type every stream in this package
// carries. Payload/Payloads are opaque - never interpreted here, only
// routed by Type/From. Payload is used by the message types that carry one
// blob (MsgPreprocessing, MsgStart); Payloads by the ones that carry one
// per lock-step session (MsgRound1/2/3).
type Envelope struct {
	Type     MsgType
	From     int // 1-indexed party index of the sender
	Payload  []byte
	Payloads [][]byte
	Reason   string // set only on MsgAbort
}

// encodeEnvelope gob-encodes env into a self-contained byte slice.
func encodeEnvelope(env Envelope) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(env); err != nil {
		return nil, fmt.Errorf("network: encoding envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// decodeEnvelope is encodeEnvelope's inverse.
func decodeEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&env); err != nil {
		return Envelope{}, fmt.Errorf("network: decoding envelope: %w", err)
	}
	return env, nil
}

// PreprocessingBundle is what the leader sends one peer in a
// MsgPreprocessing Envelope: that peer's KeyState (unchanged across
// repeats) and its PreprocessingState for every session in this repeat,
// indexed 0..numSessions-1.
type PreprocessingBundle struct {
	Key      tmprotocol.KeyState
	Sessions []tmprotocol.PreprocessingState
}

// encodeBundle/decodeBundle gob-encode/decode a PreprocessingBundle
// into/from the opaque []byte a MsgPreprocessing Envelope carries.
func encodeBundle(b PreprocessingBundle) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(b); err != nil {
		return nil, fmt.Errorf("network: encoding PreprocessingBundle: %w", err)
	}
	return buf.Bytes(), nil
}

func decodeBundle(data []byte) (PreprocessingBundle, error) {
	var b PreprocessingBundle
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&b); err != nil {
		return PreprocessingBundle{}, fmt.Errorf("network: decoding PreprocessingBundle: %w", err)
	}
	return b, nil
}

// NewHost creates one libp2p host with a fresh Ed25519 identity, listening
// on listenAddrs (each a multiaddr string, e.g. "/ip4/0.0.0.0/tcp/4001") -
// the full default transport/security/mux stack. No DHT/mDNS, NAT
// traversal, relay, or persisted long-term identity: the party set is
// closed and known up front, addresses shared out of band (see
// cmd/tmldsa-network), and a fresh identity every run is all a timing
// harness needs. With no listenAddrs given, defaults to loopback TCP on an
// OS-assigned port, matching this package's local test harness.
func NewHost(listenAddrs ...string) (host.Host, error) {
	if len(listenAddrs) == 0 {
		listenAddrs = []string{"/ip4/127.0.0.1/tcp/0"}
	}

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("network: generating identity: %w", err)
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(listenAddrs...),
	)
	if err != nil {
		return nil, fmt.Errorf("network: creating host: %w", err)
	}
	return h, nil
}

// sendEnvelope opens a fresh stream to peerID and writes env on it. One
// stream per message: each send is independently timeable/cancelable,
// which matters both for the timing this package measures and for keeping
// abort latency low.
func sendEnvelope(ctx context.Context, h host.Host, peerID peer.ID, env Envelope) error {
	s, err := h.NewStream(ctx, peerID, StreamProtocolID)
	if err != nil {
		return fmt.Errorf("network: opening stream to %s: %w", peerID, err)
	}
	defer s.Close()

	packed, err := encodeEnvelope(env)
	if err != nil {
		return err
	}
	if _, err := s.Write(packed); err != nil {
		return fmt.Errorf("network: writing envelope to %s: %w", peerID, err)
	}
	return nil
}

// readEnvelope reads one Envelope off s. Decodes straight from the stream
// (rather than buffering via io.ReadAll first) so it doesn't depend on the
// sender closing its write side - gob.Decoder already knows exactly how
// many bytes one Encode call wrote.
func readEnvelope(s network.Stream) (Envelope, error) {
	var env Envelope
	if err := gob.NewDecoder(s).Decode(&env); err != nil {
		return Envelope{}, fmt.Errorf("network: reading envelope: %w", err)
	}
	return env, nil
}
