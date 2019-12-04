extern crate criterion;

use bls_eth_rust::*;
use criterion::{black_box, criterion_group, criterion_main, Benchmark, Criterion};

pub const SECRET_KEY_SERIALIZED: [u8; 32] = [
    71, 184, 25, 45, 119, 191, 135, 27, 98, 232, 120, 89, 214, 83, 146, 39, 37, 114, 74, 92, 3, 26,
    254, 171, 198, 11, 206, 245, 255, 102, 81, 56,
];
pub const MSG: [u8; 96] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 87, 33, 13, 72, 155, 73, 4, 185, 87, 46, 230,
    247, 159, 191, 7, 148, 85, 120, 129, 175, 102, 169, 241, 139, 189, 44, 244, 68, 119, 60, 28,
    101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 225, 95, 237, 38, 188, 142, 181, 147, 233,
    183, 232, 13, 219, 92, 94, 79, 19, 174, 172, 105, 133, 207, 4, 113, 115, 242, 140, 138, 44,
    215, 244, 77,
];
pub const SIGNATURE_SERIALIZED: [u8; 96] = [
    185, 209, 191, 146, 27, 61, 208, 72, 189, 206, 56, 194, 206, 172, 42, 42, 128, 147, 200, 100,
    136, 31, 36, 21, 242, 43, 25, 141, 233, 53, 255, 167, 145, 112, 120, 85, 193, 101, 109, 194,
    26, 122, 242, 213, 2, 187, 70, 89, 1, 81, 214, 69, 240, 98, 99, 76, 59, 44, 183, 156, 78, 209,
    196, 164, 184, 179, 241, 159, 15, 92, 118, 150, 92, 101, 21, 83, 232, 61, 21, 63, 249, 83, 83,
    115, 81, 86, 239, 247, 118, 146, 247, 166, 42, 230, 83, 251,
];

fn signing(c: &mut Criterion) {
    init(CurveType::BLS12_381);
    let seckey = SecretKey::from_serialized(&SECRET_KEY_SERIALIZED).unwrap();

    let pubkey = seckey.get_publickey();
    let sig = seckey.sign_hash(&MSG).unwrap();

    c.bench(
        "signing",
        Benchmark::new("Create a Signature", move |b| {
            b.iter(|| {
                black_box(seckey.sign_hash(&MSG).unwrap());
            })
        })
        .sample_size(10),
    );

    c.bench(
        "signing",
        Benchmark::new("Verify a Signature", move |b| {
            b.iter(|| {
                black_box(sig.verify_hash(&pubkey, &MSG));
            })
        })
        .sample_size(10),
    );
}

fn compression(c: &mut Criterion) {
    init(CurveType::BLS12_381);
    let seckey = SecretKey::from_serialized(&SECRET_KEY_SERIALIZED).unwrap();

    let sig = seckey.sign_hash(&MSG).unwrap();

    c.bench(
        "compression",
        Benchmark::new("Serialize a Signature", move |b| {
            b.iter(|| {
                black_box(sig.serialize());
            })
        })
        .sample_size(10),
    );

    c.bench(
        "compression",
        Benchmark::new("Decompress a Signature", move |b| {
            b.iter(|| {
                black_box(Signature::from_serialized(&SIGNATURE_SERIALIZED).unwrap());
            })
        })
        .sample_size(10),
    );
}

fn aggregation(c: &mut Criterion) {
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
