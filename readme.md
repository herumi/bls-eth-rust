# bls-eth for Rust

This is a wrapper library of [bls](https://github.com/herumi/bls/) with `BLS_ETH=1`.

# How to build `libbls384_256.a`

copy from [bls-eth-go-binary/bls/lib](https://github.com/herumi/bls-eth-go-binary/tree/master/bls/lib) or build it at yourself according to [readme.md](https://github.com/herumi/bls-eth-go-binary#how-to-build-the-static-binary).

# News
The new [eth2.0 functions](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/beacon-chain.md#bls-signatures) are supported.

bls-eth-rust | eth2.0 spec name|
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
env RUSTFLAGS="-L../bls-eth-go-binary/bls/lib/linux/amd64/" cargo test
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
