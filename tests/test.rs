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

    let msg = Message::zero();
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let pubkey = seckey.get_publickey();
    let sig = seckey.sign_message(&msg).unwrap();
    assert!(sig.verify_message(&pubkey, &msg));

    serialize_test! {SecretKey, seckey};
    serialize_test! {PublicKey, pubkey};
    serialize_test! {Signature, sig};
}

#[test]
fn test_aggregate() {
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let pubkey = seckey.get_publickey();
    let mut msg = Message::zero();
    msg.hash[0] = 1;
    let sig = seckey.sign_message(&msg).unwrap();
    assert!(sig.verify_message(&pubkey, &msg));

    const N: usize = 10;
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
    for i in 1..N {
        agg_sig.add_assign(&sigs[i])
    }
    assert!(agg_sig.verify_aggregated_message(&pubs[..], &msgs[..]));
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
    set_eth_mode(EthModeType::Draft05);
    const N: usize = 3;
    const MSG_TBL:[&str;N] = [
		"b2a0bd8e837fc2a1b28ee5bcf2cddea05f0f341b375e51de9d9ee6d977c2813a5c5583c19d4e7db8d245eebd4e502163076330c988c91493a61b97504d1af85fdc167277a1664d2a43af239f76f176b215e0ee81dc42f1c011dc02d8b0a31e32",
		"b2deb7c656c86cb18c43dae94b21b107595486438e0b906f3bdb29fa316d0fc3cab1fc04c6ec9879c773849f2564d39317bfa948b4a35fc8509beafd3a2575c25c077ba8bca4df06cb547fe7ca3b107d49794b7132ef3b5493a6ffb2aad2a441",
		"a1db7274d8981999fee975159998ad1cc6d92cd8f4b559a8d29190dad41dc6c7d17f3be2056046a8bcbf4ff6f66f2a360860fdfaefa91b8eca875d54aca2b74ed7148f9e89e2913210a0d4107f68dbc9e034acfc386039ff99524faf2782de0e"];
    let sig_hex = "973ab0d765b734b1cbb2557bcf52392c9c7be3cd21d5bd28572d99f618c65e921f0dd82560cc103feb9f000c23c00e660e1364ed094f137e1045e73116cd75903af446df3c357540a4970ec367a7f7fa7493a5db27ca322c48d57740908585e8";
    let mut sigs = [unsafe { Signature::uninit() }; N];
    for i in 0..N {
        sigs[i] = signature_deserialize_hex_str(&MSG_TBL[i]);
    }
    let mut agg_sig = unsafe { Signature::uninit() };
    agg_sig.aggregate(&sigs);
    assert_eq!(signature_serialize_to_hex_str(&agg_sig), sig_hex);
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
    set_eth_mode(EthModeType::Draft05);
    let mut sec_hex =
        "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138".to_string();
    let mut msg_hex =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let mut sig_hex = "b2deb7c656c86cb18c43dae94b21b107595486438e0b906f3bdb29fa316d0fc3cab1fc04c6ec9879c773849f2564d39317bfa948b4a35fc8509beafd3a2575c25c077ba8bca4df06cb547fe7ca3b107d49794b7132ef3b5493a6ffb2aad2a441".to_string();

    one_test_eth_sign(&sec_hex, &msg_hex, &sig_hex);
    let f = File::open("tests/sign.txt").unwrap();
    let file = BufReader::new(&f);
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
    set_eth_mode(EthModeType::Draft05);
    const N: usize = 3;
    const PUB_TBL:[&str;N] = [
		"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
		"b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
		"b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
	];
    const MSG_TBL: [&str; N] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "5656565656565656565656565656565656565656565656565656565656565656",
        "abababababababababababababababababababababababababababababababab",
    ];
    let sig_hex = "82f5bfe5550ce639985a46545e61d47c5dd1d5e015c1a82e20673698b8e02cde4f81d3d4801f5747ad8cfd7f96a8fe50171d84b5d1e2549851588a5971d52037218d4260b9e4428971a5c1969c65388873f1c49a4c4d513bdf2bc478048a18a8";
    let sig = signature_deserialize_hex_str(&sig_hex);
    let mut pubs = [unsafe { PublicKey::uninit() }; N];
    let mut msg_hex: String = "".to_string();
    for i in 0..N {
        pubs[i] = publickey_deserialize_hex_str(&PUB_TBL[i]);
        msg_hex.push_str(&MSG_TBL[i]);
    }
    let msgs = hex::decode(&msg_hex).unwrap();
    assert!(are_all_msg_different(&msgs, 32));
    assert!(sig.aggregate_verify_no_check(&pubs, &msgs));
}

#[test]
fn test_fast_aggregate_verify() {
    set_eth_mode(EthModeType::Draft05);
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
    set_eth_mode(EthModeType::Draft05);
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
    set_eth_mode(EthModeType::Draft05);
    let tbl = [0, 1, 2, 15, 16, 17, 50];
    for i in 0..tbl.len() {
        one_test_eth_aggregate_verify_no_check(tbl[i]);
    }
}

#[test]
fn test_eth_draft06() {
    set_eth_mode(EthModeType::Draft06);
    let seckey = SecretKey::from_hex_str("1").unwrap();
    let sig = seckey.sign("asdf".as_bytes());
    let sig_hex = "8c858cfbec5fed26cdf9368337900a7bec132b4356e959d9e94b8e9178f8669598a46cd12eadf2226d796f6429b527fc067112244c2b15f3b7f6d5f6304c51a7b087664eaabc3c76e745daeafe6930f5699a6a0d4a24486aa886b3770a63ed32";

    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}

#[test]
fn test_eth_draft07() {
    set_eth_mode(EthModeType::Draft07);
    let seckey = SecretKey::from_hex_str("1").unwrap();
    let sig = seckey.sign("asdf".as_bytes());
    let sig_hex = "b45a264e0d6f8614c4640ea97bae13effd3c74c4e200e3b1596d6830debc952602a7d210eca122dc4f596fa01d7f6299106933abd29477606f64588595e18349afe22ecf2aeeeb63753e88a42ef85b24140847e05620a28422f8c30f1d33b9aa";
    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}
