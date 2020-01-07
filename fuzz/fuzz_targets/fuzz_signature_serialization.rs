#![no_main]
use libfuzzer_sys::fuzz_target;
use bls_eth_rust::Signature;

fuzz_target!(|data: &[u8]| {
    let _sig = Signature::from_serialized(data);
});
