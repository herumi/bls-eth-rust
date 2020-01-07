#![no_main]
use libfuzzer_sys::fuzz_target;
use bls_eth_rust::PublicKey;

fuzz_target!(|data: &[u8]| {
    let _pk = PublicKey::from_serialized(data);
});
