[![Build Status](https://github.com/herumi/bls-eth-rust/actions/workflows/main.yml/badge.svg)](https://github.com/herumi/bls-eth-rust/actions/workflows/main.yml)

# bls-eth for Rust

This is a wrapper library of [bls](https://github.com/herumi/bls/) with `BLS_ETH=1`.

# News
- 2020/May/19 : The default hash function has changed to the function defined at [draft-irtf-cfrg-hash-to-curve](https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.txt) ([BLS12381G2_XMD:SHA-256_SSWU_RO_](https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-07.html#name-bls12381g2_xmdsha-256_sswu_)).

# API

bls-eth-rust | old eth2.0 spec name|
------|-----------------|
SecretKey::sign|Sign|
PublicKey::verify|Verify|
Signature::aggregate|Aggregate|
Signature::fast_aggregate_verify|FastAggregateVerify|
Signature::aggregate_verify_no_check|AggregateVerify|

Check functions:
- `verify_signature_order` -- make `deserialize` check the correctness of the order
- `Signature::is_valid_order` -- check the correctness of the order
- `verify_publickey_order` -- make `deserialize` check the correctness of the order
- `PublicKey::is_valid_order` -- check the correctness of the order
- `are_all_msg_different` -- check that all messages are different from each other

# How to build and test

## Linux / macOS

Install nasm for x86-64 environments.

```
git submodule update --init --recursive
cargo test
```

## Windows (MSVC)

Open a Developer Command Prompt (or run `vcvars64.bat`) so that `cl` and `lib` are in PATH.
Install nasm for x86-64 environments.
`build.rs` automatically runs `mklib.bat eth` inside the `bls` directory to produce `bls/lib/bls384_256.lib`.

```
git submodule update --init --recursive
cargo test
```

## Windows (GNU / MinGW)

```
set RUSTFLAGS=-L../bls-eth-go-binary/bls/lib/windows/amd64
cargo test --target=x86_64-pc-windows-gnu
```

# How to run benchmarks

```
cargo bench
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

MITSUNARI Shigeo(herumi@nifty.com)

## Sponsors welcome
[GitHub Sponsor](https://github.com/sponsors/herumi)
