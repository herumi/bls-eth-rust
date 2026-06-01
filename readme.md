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

**You must build from a Developer Command Prompt for VS**, so that MSVC tools (`cl`, `lib`, `link`) take priority in PATH.

How to open one:
- Start menu → search **"Developer Command Prompt for VS 20xx"**, or
- Run `vcvars64.bat` in an existing prompt (e.g. `"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"`).

Install nasm for x86-64 environments.
`build.rs` automatically runs `mklib.bat eth` inside the `bls` directory to produce `bls/lib/bls384_256.lib`.

```
git submodule update --init --recursive
cargo test
```

### Troubleshooting: wrong `link.exe` is used

If you see an error like `link: missing operand` or `bls384_256.dll not found`, Git for Windows' `link.exe` may be shadowing MSVC's `link.exe`.

Check which `link.exe` is found first:

```
where link.exe
```

The first line must point to the MSVC linker, e.g.:

```
C:\Program Files\Microsoft Visual Studio\...\VC\Tools\MSVC\...\bin\HostX64\x64\link.exe
```

If instead it shows `C:\Program Files\Git\usr\bin\link.exe` first, open a Developer Command Prompt as described above and try again. The VS environment script ensures MSVC tools precede Git tools in PATH.

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
