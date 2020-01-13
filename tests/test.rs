use bls_eth_rust::*;
use std::mem;

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
