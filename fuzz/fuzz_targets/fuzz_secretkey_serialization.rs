#![no_main]
use libfuzzer_sys::fuzz_target;
use bls_eth_rust::SecretKey;

fuzz_target!(|data: &[u8]| {
    let _sk = SecretKey::from_serialized(data);
});
