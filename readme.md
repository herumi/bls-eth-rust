# bls-eth for Rust

This is a wrapper library of [bls](https://github.com/herumi/bls/) with `BLS_ETH=1`.

*Remark* : This is beta version.

# How to build `libbls384_256.a`

copy from [bls-eth-go-binary/bls/lib](https://github.com/herumi/bls-eth-go-binary/tree/master/bls/lib) or build it at yourself according to [readme.md](https://github.com/herumi/bls-eth-go-binary#how-to-build-the-static-binary).

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

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)
