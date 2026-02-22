# boring2

[![crates.io](https://img.shields.io/crates/v/boring2.svg)](https://crates.io/crates/boring2)

BoringSSL bindings for the Rust programming language and TLS adapters for [tokio](https://github.com/tokio-rs/tokio).

It supports [FIPS-compatible builds of BoringSSL](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md),
as well as [Post-Quantum crypto](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
and [Raw Public Key](https://docs.rs/boring/latest/boring/ssl/struct.SslRef.html#method.peer_pubkey) extensions.

## Documentation
 - Boring API: <https://docs.rs/boring2>
 - tokio TLS adapters: <https://docs.rs/tokio-boring2>
 - FFI bindings: <https://docs.rs/boring-sys2>

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [boring](https://github.com/cloudflare/boring).
