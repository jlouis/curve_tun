# Implementation details

The Erlang code uses the `enacl` library for all its low-level cryptographic work. These are bindings to the NaCl/libsodium libraries. On top of this, the code implements a high-level packet-oriented protocol which uses the cryptographic primitives to secure the socket connection on the wire. See the document PROTOCOL.md for the protocol description and its security properties.

This document describes the construction of the Erlang system.

# General considerations

Currently, our system does a miserable job at throwing out old key data. In particular, if an attacker can gain memory access to a system, he may be able to grab even very old key data and obtain it. We plan on creating more safe vaults with overwriting capability in the future, but for now, we use the Erlang subsystem for ease of use.

# Specific processes

## Vault

A clients key is kept in a specialized process called the *vault*. This process is the only one who stores the secret key of the system. No provision has been made to protect this process against scrutiny from the shell, so if you have shell-access to the Erlang system, the secret key is known.

The design, however, is such that you can hide the secret key in various ways in your system. Either by implementing a hidden C node, or by hiding the key material behind a NIF, or something like that. By keeping the *vault* separate from the rest of the code, and by doing all secret-key cryptographic work in the vault, we make sure we can store the key differently later on. A good candidate is a hardware security module for instance.

The vault can box and open boxes pertaining to the secret key of `curve_tun`. While doing so, it also constructs long-term Nonce's according to the PROTOCOL.md specification. It always returns the box and the used Nonce to make it easy to incorporate into packets.

The vault tracks:

* Public/Secret key pairs of long-term keys.
* Counters for the long-term keys for nonce generation.
* The nonce block-key for scrambling the counter so it doesn't leak out.

## Cookie key process

A separate process maintain a cookie key generated at random. The key is cycled once in a minute, but older keys are kept for a minute. This key is used to decrypt cookies when they come in from the client. If the key has been cycled in the meantime, the older keys are tried.

The brilliance of the protocol is that cookies contain all information to construct the connection. So if used over a datagram protocol like UDP, the cookie acts like a SYN-cookie of TCP but encrypted. The client bears the burden of establishing the connection.

The security implications are that once a key is recycled, it is gone. This means that while the server needs protection, it doesn't track keys long-term and thus is less of a problem.

## The registry

There is a process which handles the peer registry. This is akin to the file `$HOME/.ssh/known_hosts` in the SSH system. It maps from IP addresses into Public keys for those addresses. In a future variant of the system, it is possible to use different kinds of registries. For instance a registry mapping into DNS and thus binding the keys into the infrastructure.

The registry must be protected against forgery on the endpoint. But apart from that, there are few security considerations. The registry only contains public keys of other clients, and possessing these should not damage anyone.

## Connection

Connection processes implement an FSM which runs the connection system. There are the following two possible transition chains:

	server: ready -> accepting -> connected
	client: ready -> initiating -> connected
	
for servers and clients respectively. Furthermore, there is a 'closed' state we can transition to from any state if the TCP connection is shut down.

The process implements something looks a *lot* like a gen_tcp connection, but it does differ in that it provides a message-oriented interface over the socket. Future implementations might reinvigorate the stream nature on top of this protocol.

Multiple receivers are processed in FIFO order of their call to the `recv/1` function.



