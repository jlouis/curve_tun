# Implementation details

The Erlang code uses the `enacl` library for all its low-level cryptographic work. These are bindings to the NaCl/libsodium libraries. On top of this, the code implements a high-level packet-oriented protocol which uses the cryptographic primitives to secure the socket connection on the wire. See the document PROTOCOL.md for the protocol description and its security properties.

This document describes the construction of the Erlang system.

## Vault

A clients key is kept in a specialized process called the *vault*. This process is the only one who stores the secret key of the system. No provision has been made to protect this process against scrutiny from the shell, so if you have shell-access to the Erlang system, the secret key is known.

The design, however, is such that you can hide the secret key in various ways in your system. Either by implementing a hidden C node, or by hiding the key material behind a NIF, or something like that. By keeping the *vault* separate from the rest of the code, and by doing all secret-key cryptographic work in the vault, we make sure we can store the key differently later on. A good candidate is a hardware security module for instance.
