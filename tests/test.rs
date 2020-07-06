use bls_eth_rust::*;
use hex;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::mem;

fn secretkey_deserialize_hex_str(x: &str) -> SecretKey {
    SecretKey::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

#[allow(dead_code)]
fn secretkey_serialize_to_hex_str(x: &SecretKey) -> String {
    hex::encode(x.serialize())
}

fn publickey_deserialize_hex_str(x: &str) -> PublicKey {
    PublicKey::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

#[allow(dead_code)]
fn publickey_serialize_to_hex_str(x: &PublicKey) -> String {
    hex::encode(x.serialize())
}

fn signature_deserialize_hex_str(x: &str) -> Signature {
    Signature::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn signature_serialize_to_hex_str(x: &Signature) -> String {
    hex::encode(x.serialize())
}

#[test]
fn test_are_all_msg_different() {
    assert!(are_all_msg_different("abcdefgh".as_bytes(), 2));
    assert!(!are_all_msg_different("abcdabgh".as_bytes(), 2));
}

macro_rules! serialize_test {
    ($t:ty, $x:expr) => {
        let buf = $x.serialize();
        let mut y: $t = unsafe { <$t>::uninit() };
        assert!(y.deserialize(&buf));
        assert_eq!($x, y);

        let z = <$t>::from_serialized(&buf);
        assert_eq!($x, z.unwrap());
    };
}

#[test]
fn test_sign_serialize() {
    assert_eq!(mem::size_of::<SecretKey>(), 32);
    assert_eq!(mem::size_of::<PublicKey>(), 48 * 3);
    assert_eq!(mem::size_of::<Signature>(), 48 * 2 * 3);

    let msg = "abc".as_bytes();
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let pubkey = seckey.get_publickey();
    let sig = seckey.sign(&msg);
    assert!(sig.verify(&pubkey, &msg));

    serialize_test! {SecretKey, seckey};
    serialize_test! {PublicKey, pubkey};
    serialize_test! {Signature, sig};
}

#[test]
fn test_from_serialized_signature() {
    let data = [0u8; 0];
    let _sig = Signature::from_serialized(&data);
}

#[test]
fn test_from_serialized_publickey() {
    let data = [0u8; 0];
    let _pk = PublicKey::from_serialized(&data);
}

#[test]
fn test_eth_aggregate() {
    let f = File::open("tests/aggregate.txt").unwrap();
    let file = BufReader::new(&f);
    let mut sigs: Vec<Signature> = Vec::new();

    for (_, s) in file.lines().enumerate() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "sig" => sigs.push(signature_deserialize_hex_str(&v[1])),
            "out" => {
                let out = signature_deserialize_hex_str(&v[1]);
                let mut agg = unsafe { Signature::uninit() };
                agg.aggregate(&sigs);
                sigs.clear();
                assert_eq!(agg, out);
            }
            _ => assert!(false),
        }
    }
}

fn one_test_eth_sign(sec_hex: &str, msg_hex: &str, sig_hex: &str) {
    let seckey = secretkey_deserialize_hex_str(&sec_hex);
    let pubkey = seckey.get_publickey();
    let msg = hex::decode(&msg_hex).unwrap();
    let sig = seckey.sign(&msg);
    assert!(sig.verify(&pubkey, &msg));
    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}

#[test]
fn test_eth_sign() {
    let f = File::open("tests/sign.txt").unwrap();
    let file = BufReader::new(&f);
    let mut sec_hex = "".to_string();
    let mut msg_hex = "".to_string();
    let mut sig_hex;
    for (_, s) in file.lines().enumerate() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "sec" => sec_hex = v[1].to_string(),
            "msg" => msg_hex = v[1].to_string(),
            "out" => {
                sig_hex = v[1].to_string();
                one_test_eth_sign(&sec_hex, &msg_hex, &sig_hex);
            }
            _ => assert!(false),
        }
    }
}

#[test]
fn test_eth_aggregate_verify_no_check1() {
    let f = File::open("tests/aggregate_verify.txt").unwrap();
    let file = BufReader::new(&f);
    let mut pubs: Vec<PublicKey> = Vec::new();
    let mut msg: Vec<u8> = Vec::new();
    let mut sig = unsafe { Signature::uninit() };
    let mut valid = false;

    let mut i = 0;
    for (_, s) in file.lines().enumerate() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "pub" => pubs.push(publickey_deserialize_hex_str(&v[1])),
            "msg" => {
                let vv = hex::decode(&v[1]).unwrap();
                msg.append(&mut vv.clone());
            }
            "sig" => {
                valid = sig.deserialize(&hex::decode(&v[1]).unwrap());
                if !valid {
                    println!("bad signature {:?}", &v[1]);
                }
            }
            "out" => {
                println!("i={:?}", i);
                if valid {
                    let out = v[1] == "true";
                    assert_eq!(sig.aggregate_verify_no_check(&pubs, &msg), out);
                }
                pubs.truncate(0);
                msg.truncate(0);
                i += 1;
            }
            _ => assert!(false),
        }
    }
}

#[test]
fn test_fast_aggregate_verify() {
    let f = File::open("tests/fast_aggregate_verify.txt").unwrap();
    let file = BufReader::new(&f);
    let mut pubs: Vec<PublicKey> = Vec::new();
    let mut sig = unsafe { Signature::uninit() };
    let mut msg: Vec<u8> = Vec::new();
    let mut valid = false;

    let mut i = 0;
    for (_, s) in file.lines().enumerate() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "pub" => pubs.push(publickey_deserialize_hex_str(&v[1])),
            "msg" => {
                let vv = &hex::decode(&v[1]).unwrap();
                msg = vv.clone();
            }
            "sig" => {
                valid = sig.deserialize(&hex::decode(&v[1]).unwrap());
                if !valid {
                    println!("bad signature {:?}", &v[1]);
                }
            }
            "out" => {
                println!("i={:?}", i);
                if valid {
                    let out = v[1] == "true";
                    assert_eq!(sig.fast_aggregate_verify(&pubs, &msg), out);
                }
                pubs.truncate(0);
                i += 1;
            }
            _ => assert!(false),
        }
    }
}

fn one_test_eth_aggregate_verify_no_check(n: usize) {
    const MSG_SIZE: usize = 32;
    let mut pubs: Vec<PublicKey> = Vec::new();
    let mut sigs: Vec<Signature> = Vec::new();
    let mut msgs: Vec<u8> = Vec::new();
    msgs.resize_with(n * MSG_SIZE, Default::default);
    for i in 0..n {
        let mut sec: SecretKey = unsafe { SecretKey::uninit() };
        sec.set_by_csprng();
        pubs.push(sec.get_publickey());
        msgs[MSG_SIZE * i] = i as u8;
        let sig = sec.sign(&msgs[i * MSG_SIZE..(i + 1) * MSG_SIZE]);
        sigs.push(sig);
    }
    assert!(are_all_msg_different(&msgs, MSG_SIZE));
    let mut agg_sig = unsafe { Signature::uninit() };
    agg_sig.aggregate(&sigs);
    if n == 0 {
        assert!(!agg_sig.aggregate_verify_no_check(&pubs, &msgs));
    } else {
        assert!(agg_sig.aggregate_verify_no_check(&pubs, &msgs));
        msgs[1] = 1;
        assert!(!agg_sig.aggregate_verify_no_check(&pubs, &msgs));
    }
}

#[test]
fn test_eth_aggregate_verify_no_check2() {
    let tbl = [0, 1, 2, 15, 16, 17, 50];
    for i in 0..tbl.len() {
        one_test_eth_aggregate_verify_no_check(tbl[i]);
    }
}

#[test]
fn test_eth_draft07() {
    let seckey = SecretKey::from_hex_str("1").unwrap();
    let sig = seckey.sign("asdf".as_bytes());
    let sig_hex = "b45a264e0d6f8614c4640ea97bae13effd3c74c4e200e3b1596d6830debc952602a7d210eca122dc4f596fa01d7f6299106933abd29477606f64588595e18349afe22ecf2aeeeb63753e88a42ef85b24140847e05620a28422f8c30f1d33b9aa";
    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}
