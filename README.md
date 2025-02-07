# boring2

[![crates.io](https://img.shields.io/crates/v/boring2.svg)](https://crates.io/crates/boring2)

BoringSSL bindings are available for the Rust programming language, and the HTTP [Client](https://github.com/0x676e67/rquest) is built on top of it.

## Non-goals

This package only implements the TLS extensions spec and supports the original [boring](https://github.com/cloudflare/boring) with the following features:

* Safari and Firefox required TLS extensions
* `kDHE` and `ffdhe2048`/`ffdhe3072` implementations
* Removal of `RPK` support

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.

## Accolades

The project is based on a fork of [boring](https://github.com/cloudflare/boring).
