use bls_eth_rust::*;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn signing(c: &mut Criterion) {
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let msg = "abc".as_bytes();
    let pubkey = seckey.get_publickey();
    let sig = seckey.sign(&msg);

    let mut group = c.benchmark_group("signing");
    group.sample_size(10);

    group.bench_function("Create a Signature", |b| {
        b.iter(|| black_box(seckey.sign(&msg)))
    });

    group.bench_function("Verify a Signature", |b| {
        b.iter(|| black_box(sig.verify(&pubkey, &msg)))
    });

    group.finish();
}

fn compression(c: &mut Criterion) {
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let msg = "abc".as_bytes();
    let sig = seckey.sign(&msg);
    let s = sig.serialize();

    let mut group = c.benchmark_group("compression");
    group.sample_size(10);

    group.bench_function("Serialize a Signature", |b| {
        b.iter(|| black_box(sig.serialize()))
    });

    group.bench_function("Decompress a Signature", |b| {
        b.iter(|| black_box(Signature::from_serialized(&s).unwrap()))
    });

    group.finish();
}

fn aggregation(c: &mut Criterion) {
    set_eth_mode(EthModeType::Old);
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let pubkey = seckey.get_publickey();
    let msg = "hello".as_bytes();
    let sig = seckey.sign(&msg);
    assert!(sig.verify(&pubkey, &msg));

    const N: usize = 128;
    let mut pubs = [unsafe { PublicKey::uninit() }; N];
    let mut sigs = [unsafe { Signature::uninit() }; N];

    let mut msgs: Vec<u8> = vec![0u8; 32 * N];
    for i in 0..N {
        seckey.set_by_csprng();
        pubs[i] = seckey.get_publickey();
        msgs[32 * i] = i as u8;
        sigs[i] = seckey.sign(&msgs[32 * i..32 * (i + 1)]);
    }
    let mut agg_sig = sigs[0];
    let mut agg_pub = pubs[0];
    for i in 1..N {
        agg_sig.add_assign(&sigs[i]);
        agg_pub.add_assign(&pubs[i]);
    }

    let mut tmp_agg_sig = sigs[0];
    let mut tmp_agg_pub = pubs[0];

    let mut group = c.benchmark_group("aggregation");
    group.sample_size(10);

    group.bench_function("Aggregate 128 Signatures", |b| {
        b.iter(|| {
            black_box({
                for i in 1..N {
                    tmp_agg_sig.add_assign(&sigs[i])
                }
            })
        })
    });

    group.bench_function("Aggregate 128 Public Keys", |b| {
        b.iter(|| {
            black_box({
                for i in 1..N {
                    tmp_agg_pub.add_assign(&pubs[i])
                }
            })
        })
    });

    group.bench_function("Verify 128 Public Keys and 128 Messages", |b| {
        b.iter(|| black_box(agg_sig.aggregate_verify_no_check(&pubs, &msgs)))
    });

    group.finish();
}

criterion_group!(benches, signing, compression, aggregation);
criterion_main!(benches);
