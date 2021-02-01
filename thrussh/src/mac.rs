use cryptovec::CryptoVec;
use hmac::{Hmac, Mac};
use hmac::crypto_mac::MacError;
use sha2::Sha256;
use std::error::Error;

use crate::sshbuffer::SSHBuffer;

type HmacSha256 = Hmac<Sha256>;

const KEY_BYTES: usize = 32;
const BLOCK_BYTES: usize = 32;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl Name {
    pub fn get_str(self) -> &'static str {
        self.0
    }
}

#[allow(non_snake_case)]
pub mod NONE {
    pub const NAME: super::Name = super::Name("none");
}

/// The name of the hmac-sha2-512 algorithm for SSH.
#[allow(non_snake_case)]
pub mod HMAC_SHA2_256 {
    pub const NAME: super::Name = super::Name("hmac-sha2-256");
}

pub struct HmacSha256Builder {
    pub name: Name,
    pub key_len: usize,
    pub make_integrity_key_verify: fn(key: &[u8]) -> HmacSha256,
    pub make_integrity_key_sign: fn(key: &[u8]) -> HmacSha256,
}

#[allow(dead_code)]
fn make_integrity_key_verify(key: &[u8]) -> HmacSha256 {
    debug!("hmac verify key: {:x?}", &key);
    HmacSha256::new_varkey(&key[..KEY_BYTES])
        .expect("HMAC can take key of any size")
}

#[allow(dead_code)]
fn make_integrity_key_sign(key: &[u8]) -> HmacSha256 {
    debug!("hmac sign key: {:x?}", &key);
    HmacSha256::new_varkey(&key[..KEY_BYTES])
        .expect("HMAC can take key of any size")
}

pub static HMAC_BUILDER: HmacSha256Builder = HmacSha256Builder {
    name: HMAC_SHA2_256::NAME,
    key_len: KEY_BYTES,
    make_integrity_key_verify,
    make_integrity_key_sign,
};

#[derive(Debug)]
pub enum HMacAlgo {
    Clear,
    HmacSha256([u8; KEY_BYTES], HmacSha256),
}

impl HMacAlgo {
    // TODO: improve this
    pub fn sign(&self, d: &[u8]) -> Result<[u8; BLOCK_BYTES], Box<dyn Error>> {
        if let Self::HmacSha256(_, ref mac) = self {
            let mut mac = mac.clone();
            mac.input(d);

            // `result` has type `MacResult` which is a thin wrapper around array of
            // bytes for providing constant time equality check
            let result = mac.result();

            // To get underlying array use `code` method, but be carefull, since
            // incorrect use of the code value may permit timing attacks which defeat
            // the security provided by the `MacResult`
            Ok(result.code().into())
        } else {
            Err(Box::<dyn Error>::from("No hmac algo selected"))
        }
    }

    #[allow(dead_code)]
    pub fn verify(&self, d: &[u8], s: &[u8]) -> Result<(), MacError> {
        if let Self::HmacSha256(_, ref mac) = self {
            let mut mac = mac.clone();
            mac.input(d);
            mac.verify(s)
        } else {
            Err(MacError::default())
        }
    }
}

#[derive(Debug)]
pub struct MacPair {
    pub local_to_remote: HMacAlgo,
    pub remote_to_local: HMacAlgo,
}

impl MacPair {
    pub fn sign(&self, to_sign: &CryptoVec, buffer: &mut SSHBuffer)
    -> Result<(), Box<dyn Error>>
    {
        self.local_to_remote
            .sign(&to_sign)
            .map(|r| {
                debug!("hash: {:x?}", &r);
                buffer.buffer.extend(&r);
                ()
            })
    }

    #[allow(dead_code)]
    pub fn verify(&self, d: &[u8], s: &[u8]) -> Result<(), MacError> {
        self.remote_to_local.verify(d, s)
    }
}

pub const CLEAR_PAIR: MacPair = MacPair {
    local_to_remote: HMacAlgo::Clear,
    remote_to_local: HMacAlgo::Clear,
};
