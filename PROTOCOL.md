# Protocol Specification of CurveTun

Current version 1.0:

The purpose of `curve_tun` is to provide a secure socket communication channel over TCP. That is, the goal we are trying to fulfill is the same as the `ssl` application, but without using the complexity of `ssl`. The approach we take is to leverage the work in `CurveCP` by Dan J. Bernstein in order to provide a secure channel over TCP. Another important inspiration are OTR and its ratchet construction for forward secrecy.

This document describes the protocol specification itself. It is split into two parts. The first part describes the high-level cryptographic construction in the protocol which gives enough information to validate the protocol design itself from a cryptographic perspective. Next follows the actual data contents which describes further low level handling, which is not important for a cryptographic perspective. The specification and protocol is kept Erlang-agnostic, so it can be implemented easily by other languages. In particular, we have opted for a protocol that is easy to parse with a binary parser, and we have tried hard to eliminate any kind of parsing ambiguity, as this usually means fewer venues for errors.

Everywhere in this document, we use Erlang notation for the binary specification on the wire. The Erlang notation is succinct and precise, while providing an isomorphic description of what is on the wire, and how Erlang will be constructing/parsing the data.

# Deviations from TCP

This protocol is *NOT* a stream protocol. It works as a messaging protocol, where parties exchange messages between two endpoints. That is, a message M of K bytes sent over the connection is guaranteed to arrive in one piece M of K bytes in the other end. This choice is deliberate. While it removes the ability to use `curve_tun` as a replacement for TCP in the first place, it is usually a far better kind of messaging construction for Erlang programs.

Later versions of the protocol may define a `stream` option which can reinstate the stream-oriented messaging if we so please, on top of the underlying cryptographic messaging system.

# Bucket list

There are a number of things I'd like to address at some point in the protocol:

* The ephemeral keys are in-memory for long-running connections. If we have a BGP connection, it will last for days. This runs the problem that the ephemeral key never ever changes which means we keep the key material around for a long time. This is a security problem. A future version of the protocol will ratchet the key material forward in order to cripple these attacks.
* I would like to implement ideas of Axolotl into the protocol. This provides an excellent way to ratchet the key material while also protecting keys.
* Handle processing of large messages (i.e., messages that can't fit into a single packet).

# Protocol overview

The communication protocol proceeds, by first handshaking the connection and setting up the cryptographic channel. Then it exchanges messages on the channel. The handshake initializes a second ephermeral key-set in order to achieve forward secrecy.

A keypair is defined as `(K, Ks)` where `K` is the public part and `Ks` is the secret part. Everywhere, a key ending in the "s" character designate a secret key. We define the notation `Box[X](Cs -> S)` to mean a secure *box* primitive which *encrypts* and *authenticates* the message `X`from a client to a server. The client uses `Cs` to sign the message and uses `S` to encrypt the message destined for the server. For secret-key cryptography we define `SecretBox[X](Ks)` as a secret box encrypted (and authenticated) by the (secret) key `Ks`.

Our implementation uses the `crypto_box` primitive of NaCl/libsodium to implement `Box[…](K1s -> K2)` and uses `crypto_secretbox` to implement `SecretBox[…](KS)`.

Throughout the description, we assume a keypair `(C, Cs)` for the client and `(S, Ss)` for the server. We also use ephermeral keys for the client, `(EC, ECs)` and for the server, `(ES, ESs)`. The protocol also uses *nonces* in quite a few places and their generation are described below. First the general communication. Details follow.

It assumed the client already have access to the public key of the server, `S` and that the server already has access to the clients public key `C`.

| Client  | Server     |
|---------|------------|
| 1. Generate `(EC, ECs)` | |
| 2. Hello: send `(EC, Box[0'](ECs -> S))` | |
| | 3. Generate `(ES, ESs)` |
| | 4. Cookie ack: send `Box[ES, K](Ss -> EC)` |
| 5. Vouch: send `(K, Box[C,V](EC -> ES))` | |
| *bi-directional flow from here on out* | |
| 6. Msg: send `Box[…](ECs -> ES)` | |
| | 7. Msg: send `Box[…](ESs -> EC)` |

1. The client generates a new keypair. This keypair is ephemeral for the lifetime of the connection. Once the connection dies, the secret key of this connection is thrown away and since it never leaves the client, it means that nobody is able to understand messages on the connection from then on. This construction provides forward secrecy for the client.

2. The client advertises the ephemeral public key and boxes a set zero-values.
3. The server generates a keypair. This is also ephemeral, but on the server side. It provides forward secrecy for the server-end.
4. The server generates a cookie `K = SecretBox[EC,ESs](Ts)` where `Ts` is a secret minute key only the server knows. In other words, this is a cryptographic box which can only be understood by the holder of `Ts`. In principle, this protocol doesn't really need these kind of SYN-cookies, but it does protect the protocol against an eventual weakness in TCP and also it makes it easier to adapt the code base to CurveCP later if we want to do that. So it is kept in this protocol. The cookie doesn't need storage on the server side, which means it can't be flooded. The key `Ts` changes from time to time.
5. The client reflects the cookie and *vouches* for its key. Here `V = Box[EC](Cs -> S)`.
6. A message can be sent from the client to the server. It has to be boxed properly.
7. A message can be sent from the server to the client.

From step 6 and onwards, the message flow is bidirectional. Until connection termination, which is simply just terminating the TCP connection like one would normally do.

# Detailed protocol messaging:

This part describes the protocol contents in detail. Here we address some of the typical low-level protocol details, which are not that necessary to understand the high-level protocol construction.

Throughout this section, we use Erlang-notation for packet formats. This has the advantage packet formats are isomorphic to the code in place. Also, it means the format is formally specified and has an unambigous construction for parsing as well as unparsing.

## General protocol packet structure:

All packets are encoded with `{packet, 2}` (for non-Erlangers, this means packets are encoded as: `<<L:16/integer-big, Payload:L/binary>>`, that is 2 bytes of big-endian length followed by that many bytes of payload). Thus, the maximal packet size is 64k, and this puts limits on the size of the message in a packet. The precise message size is mentioned in the section for packets carrying messages. The 2 bytes length is the *only* length given in packets. The rest of the packet contains fixed-size lengths and everything else can be derived from the general message length. The reason for this is to avoid typical heartbleed-like attacks, where sizes are misinterpreted.

Keys in the protocol:

* `C and Cs` are the clients long-term keys.
* `S and Ss` are the servers long-term keys.
* `EC and ECs` are *ephemeral* keys generated for the connection by the client.
* `ES and ESs` are *ephemeral* keys generated for the connection by the server.

### Hello packets:

The initial packet has the following structure:

	N = 0,
	Nonce = st_nonce(hello, client, N),
	Box = enacl:box(binary:copy(<<0>>, 64), Nonce, S, ECs),
	H = <<108,9,175,178,138,169,250,252, EC:32/binary, N:64/integer, Box/binary>>

The first 8 bytes are randomly picked and identifies the connection type as a Version 1.0. It identifies we are speaking the protocol correctly from the client side. Then follows the pubkey and then follows the box, encoding 512 bits of 0. This allows graceful protocol extension in the future.

### Cookie packets:

The cookie packet has the following structure:

	Ts = curve_tun_cookie:key(),
	SafeNonce = curve_tun_vault:safe_nonce(),
	CookieNonce = <<"minute-k", SafeNonce/binary>>,

	KBox = enacl:secret_box(<<EC:32/binary, ESs:32/binary>>, CookieNonce, Ts),
	K = <<SafeNonce:16/binary, KBox/binary>>,
	Box = curve_tun_vault:box(<<ES:32/binary, K/binary>>, SafeNonce, EC),
	Cookie = <<28,69,220,185,65,192,227,246, SafeNonce:16/binary, Box/binary>>,

The 8 bytes are randomly picked and identifies the stream in the other direction as version 1.0. It allows us to roll new versions of the protocol later if needed. *Note* The long-term generated nonce is used twice in this packet with different prefixes. It is used once to make sure the cookie is protected, and once to make sure the packet is protected. The safety hinges on the safety of typical long_term nonce values, see further down for their construction.

*Note*: Once the `ES` key is in the hands of the client, the server has no need for the key anymore and it is thrown away.

### Vouch packets

Vouch packets from the client to the server have the following structure:

	K = cookie(),
	Nonce = short_term_nonce(),
	NonceLT = long_term_nonce(),
	V = box(<<EC/binary>>, NonceLT:16/binary, S, Cs),
	Box = box(<<C:32/binary, NonceLT:24/binary, V:48/binary>>, ES, ECs),
	Initiate = <<108,9,175,178,138,169,250,253, K:96/binary, Nonce:8/binary, Box/binary>>

### Message packets

Once the connection has been established, the messaging structure is much simpler. Messages have the obvious structure:

	Nonce = short_term_nonce(),
	Box = box(M, Nonce:8/binary, ES, ECs),
	Msg = <<109,27,57,203,246,90,17,180, Nonce:64/integer, Box/binary>>

The header of a message is `8+8+16 = 32` bytes. This makes the maximally sized message in the procotol `256 * 256 - 32 = 65504` bytes in size. Sending larger messages are possible if a higher-level implementation embeds chunking inside packets, but it is of no concern to the security structure of the protocol.

# Nonce handling

The protocols security is hinging on the correct usage of a number of Nonce's or number-used-just-once. If ever a nonce is reused, the security of the protocol is greatly diminished to the point of breakage. Hence, this section lays out in detail how the nonce-values are generated.

Like in CurveCP, there are four different nonce types involved:

| Key Pair | Nonce Format |
| ------------| ------------|
| The servers long-term keypair `(S, Ss)`. The client knows `S` before making a connection | The string `<<"CurveCPK">>` follow by a 16 byte compressed nonce |
| The clients long-term keypair `(C, Cs)`. Some servers can differentiate connections based on `C` | The string `<<"CurveCPV">>` followed by a 16 byte compressed nonce |
| The servers short-term keypair `(ES, ESs)`. This keypair provides forward secrecy. | The string `<<"CurveCP-server-M">>` followed by a 8 byte compressed nonce. This nonce represents a 64-bit *big-endian* number |
| The clients short-term keypair `(EC, ECs)`. Specific to the connection. | The string `<<"CurveCP-client-">>` followed by `<<"H">>`, `<<"I">>` and `<<"M">>` for Hello, Initiate and Message packets respectively. Then a 8 byte compressed nonce representing a 64 bit *big-endian* number |

## Short term keys

For short-term client keys you generate the following nonce for a message type `T`. See below for the rules about `N`:

	msg_type(hello) -> <<"H">>;
	msg_type(initiate) -> <<"I">>;
	msg_type(msg) -> <<"M">>.
	
	Type = msg_type(T),
	<<"CurveCP-client-", Type:1/binary, N:64/integer>>
	
Server-keys are likewise, but replaces `<<"CurveCP-client-">>` with `<<"CurveCP-server-">>`. The `N` is a counter counting from 0, 1, 2, … and so on. The rule is that if you reach the number `2^64` you must immediately close the connection. Note that this number is so large that a rate of 1 billion packets a second takes nearly 600 years to go through, so it should be ample.

## Long term keys

Nonces for the long-term keys are far slower moving. There are two such keys being exchanged at the moment. One for the cookie packet. And one for the vouching initiate packet from the client. They are currently generated in the same way, but they needn't be in a future protocol.

The server generates a cookie packet nonce by the following method:

	<<"CurveCPK", NonceVal:16/binary>>
	
The server is not required to generate these in order. Client messages are likewise generated:

	<<"CurveCPV", NonceVal:16/binary>>
	
Now, the `NonceVal` is generated by the following construction:

	Val = <<Counter:64/integer, Random:8/binary>>,
	encrypt(Val, Key)
	
Where the `encrypt` primitive is something like AES-256. The reason we encrypt the data is to avoid leaking the `Counter`. The counter starts from 0 and increases over time for each connection. If the system terminates in a wrong way, then the counter is not trustworthy. Hence, the system stores a counter on disk next to the key from which to start up next time around. The rule is whenever the counter C passes a multiple of 1048576 we store C+2097152 on disk and start from there if the system dies by some bad means.

## Nonce rejection

A client rejects all short-term nonces which moves backward in time. That is, the nonce counter is strictly monotonically increasing. Old messages can be ignored since it means somebody is seriously messing with TCP and trying to replay packets.

Increments does not have to be 1 and the stream doesn't have to start from 0. Clients must be prepared for this.

For long-term keys, you can't reject the nonce, since encryption makes them indistinguishable from random values.

