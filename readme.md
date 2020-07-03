[![Build Status](https://travis-ci.org/herumi/bls-eth-rust.png)](https://travis-ci.org/herumi/bls-eth-rust)
# bls-eth for Rust

This is a wrapper library of [bls](https://github.com/herumi/bls/) with `BLS_ETH=1`.

# How to build `libbls384_256.a`

copy from [bls-eth-go-binary/bls/lib](https://github.com/herumi/bls-eth-go-binary/tree/master/bls/lib) or build it at yourself according to [readme.md](https://github.com/herumi/bls-eth-go-binary#how-to-build-the-static-binary).

# News
- 2020/May/19 : The default hash function has change to the function defined at [BLS12381G2_XMD:SHA-256_SSWU_RO_](https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-07.html#name-bls12381g2_xmdsha-256_sswu_).
- The default hash function has changed to the function defined at [draft-irtf-cfrg-hash-to-curve](https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.txt).

bls-eth-rust | old eth2.0 spec name|
------|-----------------|
SecretKey::sign|Sign|
PublicKey::verify|Verify|
Signature::aggregate|Aggregate|
Signature::fast_aggregate_verify|FastAggregateVerify|
Signature::aggregate_verify_no_check|AggregateVerify|

Check functions:
- verify_signature_order ; make `deserialize` check the correctness of the order
- Signature::is_valid_order ; check the correctness of the order
- verify_publickey_order ; make `deserialize` check the correctness of the order
- PublicKey::is_valid_order ; check the correctness of the order
- are_all_msg_different ; check that all messages are different each other
# How to test

```
env RUSTFLAGS="-L<directory of libbls384_256.a>" cargo test
```

For example, on Linux,

```
mkdir work
cd work
git clone https://github.com/herumi/bls-eth-go-binary
git clone https://github.com/herumi/bls-eth-rust
cd bls-eth-rust
env RUSTFLAGS="-L../bls-eth-go-binary/bls/lib/linux/amd64/" cargo test -- --test-threads 1
```

# How to run benchs

```
env RUSTFLAGS="-L../bls-eth-go-binary/bls/lib/linux/amd64/" cargo bench
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

MITSUNARI Shigeo(herumi@nifty.com)

## Sponsors welcome
[GitHub Sponsor](https://github.com/sponsors/herumi)
