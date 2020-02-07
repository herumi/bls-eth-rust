use bls_eth_rust::*;
use hex;
use std::mem;

fn secretkey_deserialize_hex_str(x: &str) -> SecretKey {
    SecretKey::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn secretkey_serialize_to_hex_str(x: &SecretKey) -> String {
    hex::encode(x.serialize())
}

fn publickey_deserialize_hex_str(x: &str) -> PublicKey {
    PublicKey::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

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
    let sec_hex = "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138";
    let msg_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let sig_hex = "b2deb7c656c86cb18c43dae94b21b107595486438e0b906f3bdb29fa316d0fc3cab1fc04c6ec9879c773849f2564d39317bfa948b4a35fc8509beafd3a2575c25c077ba8bca4df06cb547fe7ca3b107d49794b7132ef3b5493a6ffb2aad2a441";

    one_test_eth_sign(sec_hex, msg_hex, sig_hex);
}
