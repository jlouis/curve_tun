curve_tun - TCP tunnels based on Curve25519
=====

(WARNING: This is alpha-code. Do not use it in a project. In particular, error paths in the code are not implemented)

This document describes the `curve_tun` application. It provides cryptographic tunnels over TCP in order to build secure communication between endpoints which provide *confidentiality* and *integrity* while also providing a certain amount of *availability*.

The protocol also provides *active forward secrecy* against attackers. I.e., an attacker who is a man-in-the-middle and has the ability to act and change data. Even in that case, the protocol provides forward secrecy. Naturally, this also means the protocol is safe against a *passive* adversary.

Build
-----

This project requires the `enacl` bindings which in turn requires an installed `libsodium` library. Do note that the sodium library is not a package by default in Debian/Ubuntu for instance, so you may have to build a package yourself through the use of e.g., `checkinstall`. From there on, it should be as easy as compiling with rebar:

    $ rebar3 compile

The project is using rebar3, because we need to move forward and rebar3 is a much better tool than rebar ever was.

Security
-------------

A cryptographic system is no more safe than its weakest link. There are two documents next to this one describing the used primitives and how the cryptographic safety is achieved. 

* PROTOCOL.md — describes the protocol design, which owes much, if not everything, to Dan J. Bernstein.
* IMPLEMENTATION.md — describes the Erlang implementation and its internal structure.

Current status
------------------

We are currently constructing the curve_tun application. This means a lot of things doesn't work like they are intended to do. For many primitives, we opt to get something to the point of working first, and then attack the details later on. Most notably, there are currently no strong security guarantees provided by the code:

* There is only a single vault, the dummy vault and it always use the same key material every time we want to encrypt something. This is chosen for simplicity, while we are focusing on other parts of the code base.
* The current implementation opts to leak internal counters rather than encrypt them. This will be fixed in a future version.
* safe_nonce() generation does not yet block-encrypt its counters.
* There is only a single registry, and that registry is very simplistic.
* The code has seen no testing at all, and spews dialyzer warnings left and right.

The code itself is at a stage where it can be tested for connectivity and message transfer. But we have still to provide for error paths in the code, optimizations, robustness, verification and Erlang QuickCheck.

Background
------------------

When people want to secure communication between endpoints, the ubiquituous solution is to apply SSL on the tunnel, mostly implemented by use of the OpenSSL application. While easy, it poses many problems. SSL is notoriously hard to implement correctly and furthermore, most implementations are written in C, an unsafe language in many ways. While the Erlang SSL implementation is implemented in Erlang, thus avoiding some of low-level problems, it still implements TLS, which is far from a simple protocol to implement correctly.

CurveTun or `curve_tun` implements tunnels over elliptic curve cryptography by means of the NaCl/libsodium library. It draws inspiration from Dan J. Bernsteins CurveCP implementation, but provides its tunnels over TCP—for better or worse. By being a *vastly* simpler protocol design, the hope is that it is easier to implement, which should provide better security. Also, the protocol is deliberately constructed such that it can be parsed easily. There should be no gotchas the like of Heartbleed in this protocol design.

Security considerations
------------------------------

This section addresses the security of the `curve_tun` implementation and protocol. As with everything using crypto, the biggest problem lies in the right implementation of the cryptographic primitives moreso than if the low-level facilities work. See the PROTOCOL.md description for an explanation of how the protocol is built. The document is recent and up-to-date.

As for the implementation, I can't guarantee there won't be security errors in there. The plan is to test against errors by fuzzing the implementation via Erlang QuickCheck in the future. The primary author, Jesper Louis Andersen, does have *some* cryptographic experience and is probably in the better half of the bell curve. Yet, he is no *expert* and the protocol, while being derived by one from Dan J. Bernstein, has not been thoroughly verified. Thus, the best I can do is to list the attack vectors which have been considered and mitigated.

### Requirements for correct operation:

Security protocols require a number of prerequisites to be safe. These are the ones listed for `curve_tun`.

* The random source of data must be a CSPRNG. This is true for libsodium on at least OpenBSD, FreeBSD, and Linux. OSX and iOS should also be secure with their yarrow-based generator. libsodium currently (Dec 2014) uses `RtlGenRandom()` on Windows. You will have to make sure this is safe. Likewise for other operating systems. We rely on the kernel to provide safe randomness.
* The key store vault must be writable. In order to provide safe nonces for the protocol, counters are periodically written next to the key material. While the system is safe even if using an older backup, the practice is not recommended. Furthermore, a scrambling key is written into the vault to provide protection against counters leaking to an attacker.
* The endpoints must be safe. This is a standard encrypted tunnel implementation. It does not provide any point of endpoint security, though it does provide active forward secrecy.

### Specific attack vectors:

The specific security considerations and mitigations goes here in the future. System description is not entirely done, and there are parts which have been fully implemented or verified yet.

* Server authentication: An attacker pretends to be the server. These packets are immediately rejected because they don't have either the servers long-term signature or the servers short-term signature. And the short term key is vouched for by the long-term key.
* Client authentication: An attacker pretends to be a client. Since all client communication is authenticated, with either the long-term key or a (vouched) short-term key, this is rejected by the implementation.
* No way to disable or downgrade encryption: The protocol doesn not allow for any kind of protocol downgrade, either to an earlier variant of the protocol, nor to an earlier or less safe suite of ciphers. The ciphers used are selected by Schwabe, Lange and Bernstein (between 2007–2011) and they are used as-is.
