#![no_main]
use libfuzzer_sys::fuzz_target;
use bls_eth_rust::PublicKey;

fuzz_target!(|data: &[u8]| {
    let sig = PublicKey::from_serialized(data);
});
