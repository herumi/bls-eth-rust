//! bls-eth-rust is a library to support BLS signature for Ethereum 2.0 Phase 0

//use std::mem::MaybeUninit;
use std::collections::HashSet;
use std::os::raw::c_int;
use std::sync::Once;

#[link(name = "bls384_256", kind = "static")]
#[link(name = "stdc++")]
#[allow(non_snake_case)]
extern "C" {
    // global functions
    fn blsInit(curve: c_int, compiledTimeVar: c_int) -> c_int;
    fn blsSetETHmode(mode: c_int) -> c_int;

    fn mclBn_getFrByteSize() -> u32;
    fn mclBn_getFpByteSize() -> u32;

    fn blsSecretKeySetByCSPRNG(x: *mut SecretKey);
    fn blsSecretKeySetHexStr(x: *mut SecretKey, buf: *const u8, bufSize: usize) -> c_int;
    fn blsGetPublicKey(y: *mut PublicKey, x: *const SecretKey);
    fn blsSignatureVerifyOrder(doVerify: c_int);
    fn blsSignatureIsValidOrder(sig: *const Signature) -> c_int;
    fn blsPublicKeyVerifyOrder(doVerify: c_int);
    fn blsPublicKeyIsValidOrder(pug: *const PublicKey) -> c_int;

    // for new eth2.0 spec
    fn blsSign(sig: *mut Signature, seckey: *const SecretKey, msg: *const u8, msgSize: usize);
    fn blsVerify(
        sig: *const Signature,
        pubkey: *const PublicKey,
        msg: *const u8,
        msgSize: usize,
    ) -> c_int;
    fn blsAggregateSignature(aggSig: *mut Signature, sigVec: *const Signature, n: usize);
    fn blsFastAggregateVerify(
        sig: *const Signature,
        pubVec: *const PublicKey,
        n: usize,
        msg: *const u8,
        msgSize: usize,
    ) -> c_int;
    fn blsAggregateVerifyNoCheck(
        sig: *const Signature,
        pubVec: *const PublicKey,
        msgVec: *const u8,
        msgSize: usize,
        n: usize,
    ) -> c_int;

    fn blsSecretKeyIsEqual(lhs: *const SecretKey, rhs: *const SecretKey) -> i32;
    fn blsPublicKeyIsEqual(lhs: *const PublicKey, rhs: *const PublicKey) -> i32;
    fn blsSignatureIsEqual(lhs: *const Signature, rhs: *const Signature) -> i32;

    fn blsSecretKeySerialize(buf: *mut u8, maxBufSize: usize, x: *const SecretKey) -> usize;
    fn blsPublicKeySerialize(buf: *mut u8, maxBufSize: usize, x: *const PublicKey) -> usize;
    fn blsSignatureSerialize(buf: *mut u8, maxBufSize: usize, x: *const Signature) -> usize;

    fn blsSecretKeyDeserialize(x: *mut SecretKey, buf: *const u8, bufSize: usize) -> usize;
    fn blsPublicKeyDeserialize(x: *mut PublicKey, buf: *const u8, bufSize: usize) -> usize;
    fn blsSignatureDeserialize(x: *mut Signature, buf: *const u8, bufSize: usize) -> usize;

    fn blsPublicKeyAdd(pubkey: *mut PublicKey, x: *const PublicKey);
    fn blsSignatureAdd(sig: *mut Signature, x: *const Signature);
    fn mclBnFr_isZero(x: *const SecretKey) -> i32;
}

enum CurveType {
    BLS12_381 = 5,
}

/// `EthModeType` is for `set_eth_mode`
pub enum EthModeType {
    /// before Ethereum 2.0 Phase 0
    Old = 0,
    /// Ethereum 2.0 Phase 0(eth2.0) draft05
    Draft05 = 1,
    /// Ethereum 2.0 Phase 0(eth2.0) draft06
    Draft06 = 2,
    /// Ethereum 2.0 Phase 0(eth2.0) draft07
    Draft07 = 3,
}

#[derive(Debug, PartialEq, Clone)]
/// `BlsError` type for error
pub enum BlsError {
    /// invalid data
    InvalidData,
    /// bad parameter size
    BadSize,
    /// internal error (should not happen)
    InternalError,
}

const MCLBN_FP_UNIT_SIZE: usize = 6;
const MCLBN_FR_UNIT_SIZE: usize = 4;
const BLS_COMPILER_TIME_VAR_ADJ: usize = 200;
const MCLBN_COMPILED_TIME_VAR: c_int =
    (MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE + BLS_COMPILER_TIME_VAR_ADJ) as c_int;

/// message is 32 byte in eth2.0
pub const MSG_SIZE: usize = 32;

// Used to call blsInit only once.
static INIT: Once = Once::new();
fn init_library() {
    init(CurveType::BLS12_381);
    //#[cfg(feature = "latest")]
    set_eth_mode(EthModeType::Draft07);
    //verify_signature_order(true);
}

/// return true if `size`-byte splitted `msgs` are different each other
/// * `msgs` - an array that `size`-byte messages are concatenated
/// * `size` - lenght of one message
pub fn are_all_msg_different(msgs: &[u8], size: usize) -> bool {
    let n = msgs.len() / size;
    assert!(msgs.len() == n * size);
    let mut set = HashSet::<&[u8]>::new();
    for i in 0..n {
        let msg = &msgs[i * size..(i + 1) * size];
        if set.contains(msg) {
            return false;
        }
        set.insert(msg);
    }
    return true;
}

macro_rules! common_impl {
    ($t:ty, $is_equal_fn:ident) => {
        impl PartialEq for $t {
            /// return true if `self` is equal to `rhs`
            fn eq(&self, rhs: &Self) -> bool {
                INIT.call_once(|| {
                    init_library();
                });
                unsafe { $is_equal_fn(self, rhs) == 1 }
            }
        }
        impl Eq for $t {}
        impl $t {
            /// return zero instance
            pub fn zero() -> $t {
                Default::default()
            }
            /// return uninitialized instance
            pub unsafe fn uninit() -> $t {
                std::mem::MaybeUninit::uninit().assume_init()
            }
        }
    };
}

macro_rules! serialize_impl {
    ($t:ty, $size:expr, $serialize_fn:ident, $deserialize_fn:ident) => {
        impl $t {
            /// return true if `buf` is deserialized successfully
            /// * `buf` - serialized data by `serialize`
            pub fn deserialize(&mut self, buf: &[u8]) -> bool {
                INIT.call_once(|| {
                    init_library();
                });
                unsafe { $deserialize_fn(self, buf.as_ptr(), buf.len()) > 0 }
            }
            /// return deserialized `buf`
            pub fn from_serialized(buf: &[u8]) -> Result<$t, BlsError> {
                let mut v = unsafe { <$t>::uninit() };
                if v.deserialize(buf) {
                    return Ok(v);
                }
                Err(BlsError::InvalidData)
            }
            /// return serialized byte array
            pub fn serialize(&self) -> Vec<u8> {
                INIT.call_once(|| {
                    init_library();
                });

                let size = unsafe { $size } as usize;
                let mut buf: Vec<u8> = Vec::with_capacity(size);
                let n: usize;
                unsafe {
                    n = $serialize_fn(buf.as_mut_ptr(), size, self);
                }
                if n == 0 {
                    panic!("BLS serialization error");
                }
                unsafe {
                    buf.set_len(n);
                }
                buf
            }
            /// alias of serialize
            pub fn as_bytes(&self) -> Vec<u8> {
                self.serialize()
            }
        }
    };
}

fn init(curve_type: CurveType) -> bool {
    unsafe { blsInit(curve_type as c_int, MCLBN_COMPILED_TIME_VAR) == 0 }
}

/// verify the correctness whenever signature setter is used
/// * `verify` - enable if true (default off)
pub fn verify_signature_order(verify: bool) {
    unsafe { blsSignatureVerifyOrder(verify as c_int) }
}

/// verify the correctness whenever signature setter is used
/// * `verify` - enable if true (default off)
pub fn verify_publickey_order(verify: bool) {
    unsafe { blsPublicKeyVerifyOrder(verify as c_int) }
}

//#[cfg(feature = "latest")]
/// change the mode of Ethereum specification
/// `mode` - mode of spec
pub fn set_eth_mode(mode: EthModeType) -> bool {
    unsafe { blsSetETHmode(mode as c_int) == 0 }
}

/// secret key type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SecretKey {
    d: [u64; MCLBN_FR_UNIT_SIZE],
}

/// public key type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct PublicKey {
    x: [u64; MCLBN_FP_UNIT_SIZE],
    y: [u64; MCLBN_FP_UNIT_SIZE],
    z: [u64; MCLBN_FP_UNIT_SIZE],
}

/// signature type
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Signature {
    x: [u64; MCLBN_FP_UNIT_SIZE * 2],
    y: [u64; MCLBN_FP_UNIT_SIZE * 2],
    z: [u64; MCLBN_FP_UNIT_SIZE * 2],
}

common_impl![SecretKey, blsSecretKeyIsEqual];
serialize_impl![
    SecretKey,
    mclBn_getFrByteSize(),
    blsSecretKeySerialize,
    blsSecretKeyDeserialize
];

common_impl![PublicKey, blsPublicKeyIsEqual];
serialize_impl![
    PublicKey,
    mclBn_getFpByteSize(),
    blsPublicKeySerialize,
    blsPublicKeyDeserialize
];

common_impl![Signature, blsSignatureIsEqual];
serialize_impl![
    Signature,
    mclBn_getFpByteSize() * 2,
    blsSignatureSerialize,
    blsSignatureDeserialize
];

impl SecretKey {
    /// init secret key by CSPRNG
    pub fn set_by_csprng(&mut self) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsSecretKeySetByCSPRNG(self) }
        let ret = unsafe { mclBnFr_isZero(self) };
        if ret == 1 {
            panic!("zero secretkey")
        }
    }
    /// set hexadecimal string `s` to `self`
    pub fn set_hex_str(&mut self, s: &str) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsSecretKeySetHexStr(self, s.as_ptr(), s.len()) == 0 }
    }
    /// return the secret key set by hexadecimal string `s`
    pub fn from_hex_str(s: &str) -> Result<SecretKey, BlsError> {
        let mut v = unsafe { SecretKey::uninit() };
        if v.set_hex_str(&s) {
            return Ok(v);
        }
        Err(BlsError::InvalidData)
    }
    /// return the public key corresponding to `self`
    pub fn get_publickey(&self) -> PublicKey {
        INIT.call_once(|| {
            init_library();
        });
        let mut v = unsafe { PublicKey::uninit() };
        unsafe {
            blsGetPublicKey(&mut v, self);
        }
        v
    }
    /// return the signature of `msg`
    /// * `msg` - message
    pub fn sign(&self, msg: &[u8]) -> Signature {
        INIT.call_once(|| {
            init_library();
        });
        let mut v = unsafe { Signature::uninit() };
        unsafe { blsSign(&mut v, self, msg.as_ptr(), msg.len()) }
        v
    }
}

impl PublicKey {
    /// add `x` to `self`
    /// * `x` - signature to be added
    pub fn add_assign(&mut self, x: *const PublicKey) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe {
            blsPublicKeyAdd(self, x);
        }
    }
    /// return true if `self` has the valid order
    pub fn is_valid_order(&self) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsPublicKeyIsValidOrder(self) == 1 }
    }
}

impl Signature {
    /// return true if `self` is valid signature of `msg` for `pubkey`
    /// `pubkey` - public key
    /// `msg` - message
    pub fn verify(&self, pubkey: *const PublicKey, msg: &[u8]) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsVerify(self, pubkey, msg.as_ptr(), msg.len()) == 1 }
    }
    /// add `x` to `self`
    /// * `x` - signature to be added
    pub fn add_assign(&mut self, x: *const Signature) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe {
            blsSignatureAdd(self, x);
        }
    }
    /// return true if `self` has the valid order
    pub fn is_valid_order(&self) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        unsafe { blsSignatureIsValidOrder(self) == 1 }
    }
    /// set the aggregated signature of `sigs`
    /// * `sigs` - signatures to be aggregated
    pub fn aggregate(&mut self, sigs: &[Signature]) {
        INIT.call_once(|| {
            init_library();
        });
        unsafe {
            blsAggregateSignature(self, sigs.as_ptr(), sigs.len());
        }
    }
    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msg` - message
    pub fn fast_aggregate_verify(&self, pubs: &[PublicKey], msg: &[u8]) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        if pubs.len() == 0 {
            return false;
        }
        unsafe {
            blsFastAggregateVerify(self, pubs.as_ptr(), pubs.len(), msg.as_ptr(), msg.len()) == 1
        }
    }
    fn inner_aggregate_verify(&self, pubs: &[PublicKey], msgs: &[u8], check_message: bool) -> bool {
        INIT.call_once(|| {
            init_library();
        });
        let n = pubs.len();
        if n == 0 || n * MSG_SIZE != msgs.len() {
            return false;
        }
        if check_message && !are_all_msg_different(msgs, MSG_SIZE) {
            return false;
        }
        unsafe { blsAggregateVerifyNoCheck(self, pubs.as_ptr(), msgs.as_ptr(), MSG_SIZE, n) == 1 }
    }
    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
    /// * Note - this function does not call `are_all_msg_different`
    pub fn aggregate_verify_no_check(&self, pubs: &[PublicKey], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, false)
    }
    /// return true if `self` is a valid signature of `msgs` for `pubs`
    /// * `pubs` - array of public key
    /// * `msgs` - concatenated byte `pubs.len()` array of 32-byte messages
    pub fn aggregate_verify(&self, pubs: &[PublicKey], msgs: &[u8]) -> bool {
        self.inner_aggregate_verify(pubs, msgs, true)
    }
}
