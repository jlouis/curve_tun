curve_tun - TCP tunnels based on Curve25519
=====

This document describes the `curve_tun` application. It provides cryptographic tunnels over TCP in order to build secure communication between endpoints which provide *confidentiality* and *integrity* while also providing a certain amount of *availability*.

Build
-----

    $ rebar3 compile

Current status
------------------

We are currently constructing the curve_tun application. This means a lot of things doesn't work like they are intended to do. For many primitives, we opt to get something to the point of working first, and then attack the details later on. Most notably, there are currently no strong security guarantees provided by the code:

* There is only a single vault, the dummy vault and it always use the same key material every time we want to encrypt something. This is chosen for simplicity, while we are focusing on other parts of the code base.
* The current implementation opts to leak internal counters rather than encrypt them. This will be fixed in a future version.

Background
------------------

When people want to secure communication between endpoints, the ubiquituous solution is to apply SSL on the tunnel, mostly implemented by use of the OpenSSL application. While easy, it poses many problems. SSL is notoriously hard to implement correctly and furthermore, most implementations are written in C, an unsafe language in many ways. While the Erlang SSL implementation is implemented in Erlang, thus avoiding some of low-level problems, it still implements TLS, which is far from a simple protocol to implement correctly.

CurveTun or `curve_tun` implements tunnels over elliptic curve cryptography by means of the NaCl/libsodium library. It draws inspiration from Dan J. Bernsteins CurveCP implementation, but provides its tunnels over TCP—for better or worse. By being a *vastly* simpler protocol design, the hope is that it is easier to implement, which should provide better security. Also, the protocol is deliberately constructed such that it can be parsed easily. There should be no gotchas the like of Heartbleed in this protocol design.