use bls_eth_rust::*;
use std::mem;

macro_rules! serialize_test {
    ($t:ty, $x:expr) => {
        let buf = $x.serialize();
        let mut y: $t = unsafe { <$t>::uninit() };
        assert!(y.deserialize(&buf));
        assert_eq!($x, y);
    };
}

#[test]
fn test() {
    let seckey_serialized = [
        71, 184, 25, 45, 119, 191, 135, 27, 98, 232, 120, 89, 214, 83, 146, 39, 37, 114, 74, 92, 3,
        26, 254, 171, 198, 11, 206, 245, 255, 102, 81, 56,
    ];
    let m = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 87, 33, 13, 72, 155, 73, 4, 185, 87, 46,
        230, 247, 159, 191, 7, 148, 85, 120, 129, 175, 102, 169, 241, 139, 189, 44, 244, 68, 119,
        60, 28, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 225, 95, 237, 38, 188, 142,
        181, 147, 233, 183, 232, 13, 219, 92, 94, 79, 19, 174, 172, 105, 133, 207, 4, 113, 115,
        242, 140, 138, 44, 215, 244, 77,
    ];
    let sig_serialized = [
        185, 209, 191, 146, 27, 61, 208, 72, 189, 206, 56, 194, 206, 172, 42, 42, 128, 147, 200,
        100, 136, 31, 36, 21, 242, 43, 25, 141, 233, 53, 255, 167, 145, 112, 120, 85, 193, 101,
        109, 194, 26, 122, 242, 213, 2, 187, 70, 89, 1, 81, 214, 69, 240, 98, 99, 76, 59, 44, 183,
        156, 78, 209, 196, 164, 184, 179, 241, 159, 15, 92, 118, 150, 92, 101, 21, 83, 232, 61, 21,
        63, 249, 83, 83, 115, 81, 86, 239, 247, 118, 146, 247, 166, 42, 230, 83, 251,
    ];
    assert_eq!(mem::size_of::<SecretKey>(), 32);
    assert_eq!(mem::size_of::<PublicKey>(), 48 * 3);
    assert_eq!(mem::size_of::<Signature>(), 48 * 2 * 3);
    assert!(init());

    //    let mut seckey = unsafe { SecretKey::uninit() };
    //    seckey.deserialize(&seckey_serialized);
    let seckey = SecretKey::from_serialized(&seckey_serialized).unwrap();

    let pubkey = seckey.get_publickey();
    let sig = seckey.sign_hash(&m).unwrap();
    assert!(sig.verify_hash(&pubkey, &m));
    let sig2 = Signature::from_serialized(&sig_serialized).unwrap();
    assert_eq!(sig, sig2);

    serialize_test! {SecretKey, seckey};
    serialize_test! {PublicKey, pubkey};
    serialize_test! {Signature, sig};
    test_aggregate();
}

fn test_aggregate() {
    let mut seckey = unsafe { SecretKey::uninit() };
    seckey.set_by_csprng();
    let pubkey = seckey.get_publickey();
    let hd = [1 as u8; 40];
    let sig = seckey.sign_hash_with_domain(&hd).unwrap();
    assert!(sig.verify_hash_with_domain(&pubkey, &hd));
}
