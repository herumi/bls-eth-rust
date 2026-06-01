use bls_eth_rust::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const MSG_SIZE: usize = 32;

fn make_multi_sig(n: usize, msg_size: usize) -> (Vec<PublicKey>, Vec<Signature>, Vec<u8>) {
    let mut pubs: Vec<PublicKey> = Vec::new();
    let mut sigs: Vec<Signature> = Vec::new();
    let mut msgs: Vec<u8> = Vec::new();
    msgs.resize_with(n * msg_size, Default::default);
    for i in 0..n {
        let mut sec: SecretKey = unsafe { SecretKey::uninit() };
        sec.set_by_csprng();
        pubs.push(sec.get_publickey());
        msgs[msg_size * i] = i as u8;
        let sig = sec.sign(&msgs[i * msg_size..(i + 1) * msg_size]);
        sigs.push(sig);
    }
    (pubs, sigs, msgs)
}

pub fn naieve_multi_verify(sigs: &[Signature], pubs: &[PublicKey], msgs: &[u8]) -> bool {
    let n = sigs.len();
    if n == 0 {
        return false;
    }
    for i in 0..n {
        if !sigs[i].verify(&pubs[i], &msgs[i * MSG_SIZE..(i + 1) * MSG_SIZE]) {
            return false;
        }
    }
    return true;
}

fn multi_verify(c: &mut Criterion) {
    let (pubs, sigs, msgs) = make_multi_sig(400, MSG_SIZE);
    let (pubs2, sigs2, msgs2) = make_multi_sig(400, MSG_SIZE);

    let mut group = c.benchmark_group("multi_verify");
    group.sample_size(10);

    group.bench_function("naieve", |b| {
        b.iter(|| black_box(naieve_multi_verify(&sigs, &pubs, &msgs)))
    });

    group.bench_function("multi_thread", |b| {
        b.iter(|| black_box(bls_eth_rust::multi_verify(&sigs2, &pubs2, &msgs2)))
    });

    group.finish();
}

criterion_group!(benches, multi_verify);
criterion_main!(benches);
