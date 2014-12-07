# Implementation details

The Erlang code uses the `enacl` library for all its low-level cryptographic work. These are bindings to the NaCl/libsodium libraries. On top of this, the code implements a high-level packet-oriented protocol which uses the cryptographic primitives to secure the socket connection on the wire. See the document PROTOCOL.md for the protocol description and its security properties.

This document describes the construction of the Erlang system.

## Vault

A clients key is kept in a specialized process called the *vault*. This process is the only one who stores the secret key of the system. No provision has been made to protect this process against scrutiny from the shell, so if you have shell-access to the Erlang system, the secret key is known.

The design, however, is such that you can hide the secret key in various ways in your system. Either by implementing a hidden C node, or by hiding the key material behind a NIF, or something like that. By keeping the *vault* separate from the rest of the code, and by doing all secret-key cryptographic work in the vault, we make sure we can store the key differently later on. A good candidate is a hardware security module for instance.

The vault can box and open boxes pertaining to the secret key of `curve_tun`. While doing so, it also constructs long-term Nonce's according to the PROTOCOL.md specification. It always returns the box and the used Nonce to make it easy to incorporate into packets.

## Cookie key

A separate process maintain a cookie key generated at random. The key is cycled once in a while, but older keys are kept. This key is used to decrypt cookies when they come in from the client. If the key has been cycled in the meantime, the older keys are tried which protects against reusing cookies.

The brilliance of the protocol is that cookies contain all information to construct the connection. So if used over a datagram protocol like UDP, the cookie acts like a SYN-cookie of TCP but encrypted. The client bears the burden of establishing the connection.


