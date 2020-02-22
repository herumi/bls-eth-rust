extern crate criterion;

use bls_eth_rust::*;
use criterion::{black_box, criterion_group, criterion_main, Benchmark, Criterion};

fn signing(c: &mut Criterion) {
    set_eth_mode(EthModeType::Old);
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let msg = Message::zero();
    let pubkey = seckey.get_publickey();
    let sig = seckey.sign_message(&msg).unwrap();

    c.bench(
        "signing",
        Benchmark::new("Create a Signature", move |b| {
            b.iter(|| {
                black_box(seckey.sign_message(&msg).unwrap());
            })
        })
        .sample_size(10),
    );

    c.bench(
        "signing",
        Benchmark::new("Verify a Signature", move |b| {
            b.iter(|| {
                black_box(sig.verify_message(&pubkey, &msg));
            })
        })
        .sample_size(10),
    );
}

fn compression(c: &mut Criterion) {
    set_eth_mode(EthModeType::Old);
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let msg = Message::zero();
    let sig = seckey.sign_message(&msg).unwrap();

    c.bench(
        "compression",
        Benchmark::new("Serialize a Signature", move |b| {
            b.iter(|| {
                black_box(sig.serialize());
            })
        })
        .sample_size(10),
    );

    let s = sig.serialize();
    c.bench(
        "compression",
        Benchmark::new("Decompress a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::from_serialized(&s).unwrap());
            })
        })
        .sample_size(10),
    );
}

fn aggregation(c: &mut Criterion) {
    set_eth_mode(EthModeType::Old);
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let pubkey = seckey.get_publickey();
    let mut msg = Message::zero();
    msg.hash[0] = 1;
    let sig = seckey.sign_message(&msg).unwrap();
    assert!(sig.verify_message(&pubkey, &msg));

    const N: usize = 128;
    let mut pubs = [unsafe { PublicKey::uninit() }; N];
    let mut sigs = [unsafe { Signature::uninit() }; N];

    let mut msgs: [Message; N] = [Message::zero(); N];
    for i in 0..N {
        seckey.set_by_csprng();
        pubs[i] = seckey.get_publickey();
        msgs[i].hash[0] = i as u8;
        msgs[i].domain[0] = i as u8;
        sigs[i] = seckey.sign_message(&msgs[i]).unwrap();
    }
    let mut agg_sig = sigs[0];
    let mut agg_pub = pubs[0];
    for i in 1..N {
        agg_sig.add_assign(&sigs[i]);
        agg_pub.add_assign(&pubs[i]);
    }

    let mut tmp_agg_sig = sigs[0];
    c.bench(
        "aggregation",
        Benchmark::new("Aggregate 128 Signatures", move |b| {
            b.iter(|| {
                black_box({
                    for i in 1..N {
                        tmp_agg_sig.add_assign(&sigs[i])
                    }
                });
            })
        })
        .sample_size(10),
    );

    let mut tmp_agg_pub = pubs[0];
    c.bench(
        "aggregation",
        Benchmark::new("Aggregate 128 Public Keys", move |b| {
            b.iter(|| {
                black_box({
                    for i in 1..N {
                        tmp_agg_pub.add_assign(&pubs[i])
                    }
                });
            })
        })
        .sample_size(10),
    );

    c.bench(
        "aggregation",
        Benchmark::new("Verify 128 Public Keys and 128 Messages", move |b| {
            b.iter(|| {
                black_box(agg_sig.verify_aggregated_message(&pubs[..], &msgs[..]));
            })
        })
        .sample_size(10),
    );
}

criterion_group!(benches, signing, compression, aggregation);
criterion_main!(benches);
