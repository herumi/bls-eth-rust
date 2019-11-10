# bls-eth for Rust

This is a wrapper library of [bls](https://github.com/herumi/bls/) with `BLS_ETH=1`.

# How to build `libbls384_256.a`

copy from [bls-eth-go-binary/bls/lib](https://github.com/herumi/bls-eth-go-binary/tree/master/bls/lib) or build it at yourself according to [readme.md](https://github.com/herumi/bls-eth-go-binary#how-to-build-the-static-binary).

# How to test

```
env RUSTFLAGS="-L<directory of libbls384_256.a>" cargo test
```

# License

modified new BSD License
http://opensource.org/licenses/BSD-3-Clause

# Author

光成滋生 MITSUNARI Shigeo(herumi@nifty.com)
