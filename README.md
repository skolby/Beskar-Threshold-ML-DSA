# Beskar Threshold ML-DSA

This repository contains a research prototype implementation of Threshold ML-DSA-44 signing.
The code is intended to support benchmarking for research evaluation purposes and is *NOT* ready for production use.

We implement the online phase of the Beskar Threshold ML-DSA protocol for the ML-DSA-44 parameter set in Golang. 
Core ML-DSA functionalities are adapted from the [CIRCL library](https://github.com/cloudflare/circl) and networking uses the [libp2p](https://github.com/libp2p/go-libp2p) stack.


## Code overview
Our code is contained in the following packages
 - `src/circl-ml-dsa/` - Extracted and modified ML-DSA code from the CIRCL Library. 
  The main changes are contained in `./sign/mldsa/mldsa44/protocolhooks.go` which provides accessor functions for the dealer to produce ML-DSA preprocessing material, and functions to assist in finalizing signatures.
 - `src/fields/` - A generic field arithmetic interface with various implementations.
 - `src/secretsharing/` - Secret sharing functionalities, operating over generic field types.
 - `src/uitls` - Various helper functions, including key-committing encryptions, random linear combinations and vector sharing.
 - `src/protocol` Main threshold signing functionality. Important files include:

   +  `dealer.go` - Produces and distributes preprocessing material.
   +  `thmldsa.go` - Round functions for threshold signing.
   +  `thmldsa44encoded.go` - Round functions with additional marshalling for sending messages.
 - `src/network` 

## Build 

To build an executable peer, run:
```sh
go build -o tmldsa ./src/network/cmd/
```
If building for a specific platorm other than the one you are on, you add optional flags:
```sh
GOOS=linux GOARCH=amd64 go build -o tmldsa ./src/network/cmd/
```

## Running a Peer

To run a network of signers, start the first party, which will act as the leader.

```sh
./tmldsa -n=3 -t=1 -sessions=3 -repeats=10 -message="hello, threshold ML-DSA" \
  -listen=/ip4/0.0.0.0/tcp/<PORT>
```
where `<PORT>` should be replaced with the desired port.
You must specify the following flags:

| Flag | Meaning |
|---|---|
| `-n`  | number of parties |
| `-t` |  threshold |
| `-listen` | multiaddr to listen on (default `/ip4/0.0.0.0/tcp/0`, any port) |
| `-sessions` | number of parallel sessions per signing attempt |
| `-repeats` | number of sequential repetitions |
| `-message` | the message to be signed |

Upon starting the leader will print: 
```
party 1 of 3 (leader), listening at:
  /ip4/<ADDR>/tcp/<PORT>/p2p/<Key>
start party 2 with:
  ./tmldsa -n=3 -t=1 -listen=/ip4/0.0.0.0/tcp/0 -connect=/ip4/<ADDR>/tcp/<PORT>/p2p/<Key>
```
The second party can then be started with the printed command.
Once party 2 is started it will also print how to start party 3, connecting to both of the first two parties.
