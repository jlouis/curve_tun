curve_tun - TCP tunnels based on Curve25519
=====

This document describes the `curve_tun` application. It provides cryptographic tunnels over TCP in order to build secure communication between endpoints which provide *confidentiality* and *integrity* while also providing a certain amount of *availability*.



Build
-----

    $ rebar3 compile

Background
------------------

When people want to secure communication between endpoints, the ubiquituous solution is to apply SSL on the tunnel, mostly implemented by use of the OpenSSL application. While easy, it poses many problems. SSL is notoriously hard to implement correctly and furthermore, most implementations are written in C, an unsafe language in many ways. While the Erlang SSL implementation is implemented in Erlang, thus avoiding some of low-level problems, it still implements TLS, which is far from a simple protocol to implement correctly.

CurveTun or `curve_tun` implements tunnels over elliptic curve cryptography by means of the NaCl/libsodium library. It draws inspiration from Dan J. Bernsteins CurveCP implementation, but provides its tunnels over TCP—for better or worse. By being a *vastly* simpler protocol design, the hope is that it is easier to implement, which should provide better security. Also, the protocol is deliberately constructed such that it can be parsed easily. There should be no gotchas the like of Heartbleed in this protocol design.