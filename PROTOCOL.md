# Protocol Specification of CurveTun

The purpose of `curve_tun` is to provide a secure socket communication channel over TCP. That is, the goal we are trying to fulfill is the same as the `ssl` application, but without using the complexity of `ssl`. The approach we take is to leverage the work in `CurveCP` by Dan J. Bernstein in order to provide a secure channel over TCP. Another important inspiration are OTR and its ratchet construction for forward secrecy.

This document describes the protocol specification itself. It is split into two parts. The first part describes the high-level cryptographic construction in the protocol which gives enough information to validate the protocol design itself from a cryptographic perspective. Next follows the actual data contents which describes further low level handling, which is not important for a cryptographic perspective. The specification and protocol is kept Erlang-agnostic, so it can be implemented easily by other languages. In particular, we have opted for a protocol that is easy to parse with a binary parser, and we have tried hard to eliminate any kind of parsing ambiguity, as this usually means fewer venues for errors.

Everywhere in this document, we use Erlang notation for the binary specification on the wire. The Erlang notation is succinct and precise, while providing an isomorphic description of what is on the wire, and how Erlang will be constructing/parsing the data.

# Deviations from TCP

This protocol is *NOT* a stream protocol. It works as a messaging protocol, where parties exchange messages between two endpoints. That is, a message M of K bytes sent over the connection is guaranteed to arrive in one piece M of K bytes in the other end. This choice is deliberate. While it removes the ability to use `gen_nacl` as a replacement for TCP in the first place, it is usually a far better kind of messaging construction for Erlang programs.

Later versions of the protocol may define a `stream` option which can reinstate the stream-oriented messaging if we so please, on top of the underlying cryptographic messaging system.

# Bucket list

There are a number of things I'd like to address at some point in the protocol:

* The ephemeral keys are in-memory for long-running connections. If we have a BGP connection, it will last for days. This runs the problem that the ephemeral key never ever changes which means we keep the key material around for a long time. This is a security problem. A future version of the protocol will ratchet the key material forward in order to cripple these attacks.
* I would like to implement ideas of Axolotl into the protocol. This provides an excellent way to ratchet the key material while also protecting keys.

# Protocol overview

The communication protocol proceeds, by first handshaking the connection and setting up the cryptographic channel. Then it exchanges messages on the channel. The handshake initializes a second ephermeral key-set in order to achieve forward secrecy.

A keypair is defined as `(K, k)` where `K` is the public part and `k` is the secret part. Everywhere, capital letters designate public keys. We define the notation `Box[X](c -> S)` to mean a secure *box* primitive which *encrypts* and *authenticates* the message `X`from a client to a server. The client uses `c` to sign the message and uses `S` to encrypt the message destined for the server. For secret-key cryptography we define `SecretBox[X](k)` as a secret box encrypted (and authenticated) by the (secret) key `k`.

Our implementation uses the `crypto_box` primitive of NaCl/libsodium to implement `Box[…](k -> K)` and uses `crypto_secretbox` to implement `SecretBox[…](k)`.

Throughout the description, we assume a keypair `(C, c)` for the client and `(S, s)` for the server. The protocol also uses *nonces* in quite a few places and their generation are described below. First the general communication. Details follow.

| Client  | Server     |
|---------|------------|
| 1. Generate `(C', c')` | |
| 2. Hello: send `(C', Box[0'](c' -> S))` | |
| | 3. Generate `(S', s')` |
| | 4. Cookie ack: send `Box[S', K](s -> C')` |
| 5. Vouch: send `(K, Box[C,V](c' -> S'))` | |
| *bi-directional flow from here on out* | |
| 6. Msg: send `Box[…](c' -> S')` | |
| | 7. Msg: send `Box[…](s' -> C')` |

1. The client generates a new keypair. This keypair is ephemeral for the lifetime of the connection. Once the connection dies, the secret key of this connection is thrown away and since it never leaves the client, it means that nobody is able to understand messages on the connection from then on. This construction provides forward secrecy for the client.

2. The client advertises the ephemeral public key and boxes a set zero-values.
3. The server generates a keypair. This is also ephemeral, but on the server side. It provides forward secrecy for the server-end.
4. The server generates a cookie `K = SecretBox[C',s'](t)` where `t` is a secret minute key only the server knows. In other words, this is a cryptographic box which can only be understood by the holder of `t`. In principle, this protocol doesn't really need these kind of SYN-cookies, but it does protect the protocol against an eventual weakness in TCP and also it makes it easier to adapt the code base to CurveCP later if we want to do that. So it is kept in this protocol. The cookie doesn't need storage on the server side, which means it can't be flooded. The key `t` changes from time to time.
5. The client reflects the cookie and *vouches* for its key. Here `V = Box[C'](C->S)`.
6. A message can be sent from the client to the server. It has to be boxed properly.
7. A message can be sent from the server to the client.

From step 6 and onwards, the message flow is bidirectional. Until connection termination, which is simply just terminating the TCP connection like one would normally do.

# Detailed protocol messaging:

This part describes the protocol contents in detail. Here we address some of the typical low-level protocol details, which are not that necessary to understand the high-level protocol construction.

### Hello packets:

todo.
