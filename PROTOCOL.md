# Protocol Specification of CurveTun

The purpose of `curve_tun` is to provide a secure socket communication channel over TCP. That is, the goal we are trying to fulfill is the same as the `ssl` application, but without using the complexity of `ssl`. The approach we take is to leverage the work in `CurveCP` by Dan J. Bernstein in order to provide a secure channel over TCP. Another important inspiration are OTR and its ratchet construction for forward secrecy.

This document describes the protocol specification itself. It is split into two parts. The first part describes the high-level cryptographic construction in the protocol which gives enough information to validate the protocol design itself from a cryptographic perspective. Next follows the actual data contents which describes further low level handling, which is not important for a cryptographic perspective. The specification and protocol is kept Erlang-agnostic, so it can be implemented easily by other languages. In particular, we have opted for a protocol that is easy to parse with a binary parser, and we have tried hard to eliminate any kind of parsing ambiguity, as this usually means fewer venues for errors.

Everywhere in this document, we use Erlang notation for the binary specification on the wire. The Erlang notation is succinct and precise, while providing an isomorphic description of what is on the wire, and how Erlang will be constructing/parsing the data.

# Deviations from TCP

This protocol is *NOT* a stream protocol. It works as a messaging protocol, where parties exchange messages between two endpoints. That is, a message M of K bytes sent over the connection is guaranteed to arrive in one piece M of K bytes in the other end. This choice is deliberate. While it removes the ability to use `gen_nacl` as a replacement for TCP in the first place, it is usually a far better kind of messaging construction for Erlang programs.

Later versions of the protocol may define a `stream` option which can reinstate the stream-oriented messaging if we so please, on top of the underlying cryptographic messaging system.

# Protocol overview

The communication protocol proceeds, by first handshaking the connection and setting up the cryptographic channel. Then it exchanges messages on the channel. The handshake initializes a second ephermeral key-set in order to achieve forward secrecy.

A keypair is defined as `(K, k)` where `K` is the public part and `k` is the secret part. Everywhere, capital letters designate public keys. We define the notation `Box[X](c -> S)` to mean a secure *box* primitive which *encrypts* and *authenticates* the message `X`from a client to a server. The client uses `c` to sign the message and uses `S` to encrypt the message destined for the server.

Throughout the description, we assume a keypair `(C, c)` for the client and `(S, s)` for the server. The protocol also uses *nonces* in quite a few places and their generation are described below. First the general communication. Details follow.

| Client  | Server     |
|---------|------------|
| 1. Generate (C', c') | |
| 2. Handshake: send (C', 0, Box[0'](c' -> S)) | |
| | 3. Generate (S', s') |
| | 4. Cookie ack: send Box[S', K](s -> C') |
| 5. Vouch: (K, Box[C,V](c' -> S')) | |
| 6. Msg: Box[...](c' -> S') | |
| | 7. Msg: Box[...](s' -> C') |

