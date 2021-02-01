// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use crate::{cipher, key, mac, msg};
use byteorder::{BigEndian, ByteOrder};

use crate::session::Exchange;
use cryptovec::CryptoVec;
use openssl;
use sodium;
use std::cell::RefCell;
use thrussh_keys::encoding::Encoding;

#[doc(hidden)]
pub struct Algorithm {
    local_secret: Option<sodium::scalarmult::Scalar>,
    shared_secret: Option<sodium::scalarmult::GroupElement>,
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Algorithm {{ local_secret: [hidden], shared_secret: [hidden] }}",
        )
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}
pub const CURVE25519: Name = Name("curve25519-sha256@libssh.org");

thread_local! {
    static KEY_BUF: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
    static BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

// We used to support curve "NIST P-256" here, but the security of
// that curve is controversial, see
// http://safecurves.cr.yp.to/rigid.html

impl Algorithm {
    #[doc(hidden)]
    pub fn server_dh(
        _name: Name,
        exchange: &mut Exchange,
        payload: &[u8],
    ) -> Result<Algorithm, crate::Error> {
        debug!("server_dh");

        assert_eq!(payload[0], msg::KEX_ECDH_INIT);
        let mut client_pubkey = GroupElement([0; 32]);
        {
            let pubkey_len = BigEndian::read_u32(&payload[1..]) as usize;
            client_pubkey
                .0
                .clone_from_slice(&payload[5..(5 + pubkey_len)])
        };
        debug!("client_pubkey: {:?}", client_pubkey);
        use openssl::rand::*;
        use sodium::scalarmult::*;
        let mut server_secret = Scalar([0; 32]);
        rand_bytes(&mut server_secret.0)?;
        let server_pubkey = scalarmult_base(&server_secret);

        // fill exchange.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(&server_pubkey.0);
        let shared = scalarmult(&server_secret, &client_pubkey);
        Ok(Algorithm {
            local_secret: None,
            shared_secret: Some(shared),
        })
    }

    #[doc(hidden)]
    pub fn client_dh(
        _name: Name,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<Algorithm, crate::Error> {
        use openssl::rand::*;
        use sodium::scalarmult::*;
        let mut client_secret = Scalar([0; 32]);
        rand_bytes(&mut client_secret.0)?;
        let client_pubkey = scalarmult_base(&client_secret);

        // fill exchange.
        client_ephemeral.clear();
        client_ephemeral.extend(&client_pubkey.0);

        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(&client_pubkey.0);

        Ok(Algorithm {
            local_secret: Some(client_secret),
            shared_secret: None,
        })
    }

    pub fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        let local_secret = std::mem::replace(&mut self.local_secret, None).unwrap();

        use sodium::scalarmult::*;
        let mut remote_pubkey = GroupElement([0; 32]);
        remote_pubkey.0.clone_from_slice(remote_pubkey_);
        let shared = scalarmult(&local_secret, &remote_pubkey);
        self.shared_secret = Some(shared);
        Ok(())
    }

    pub fn compute_exchange_hash<K: key::PubKey>(
        &self,
        key: &K,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<openssl::hash::DigestBytes, crate::Error> {
        // Computing the exchange hash, see page 7 of RFC 5656.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        key.push_to(buffer);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_mpint(&shared.0);
        }
        use openssl::hash::*;
        let hash = {
            let mut hasher = Hasher::new(MessageDigest::sha256())?;
            hasher.update(&buffer)?;
            hasher.finish()?
        };
        Ok(hash)
    }

    pub fn compute_keys(
        &self,
        session_id: &openssl::hash::DigestBytes,
        exchange_hash: &openssl::hash::DigestBytes,
        cipher: cipher::Name,
        mac_name: mac::Name,
        is_server: bool,
    ) -> Result<(super::cipher::CipherPair, super::mac::MacPair), crate::Error> {
        let cipher = match cipher {
            super::cipher::chacha20poly1305::NAME => &super::cipher::chacha20poly1305::CIPHER,
            super::cipher::aes128ctr::NAME => &super::cipher::aes128ctr::CIPHER,
            _ => unreachable!(),
        };
        let mac = match mac_name {
            super::mac::HMAC_SHA2_256::NAME => &super::mac::HMAC_BUILDER,
            super::mac::NONE::NAME => &super::mac::HMAC_BUILDER, // Este builder no se usa
            _ => unreachable!(),
        };

        // https://tools.ietf.org/html/rfc4253#section-7.2
        BUFFER.with(|buffer| {
            KEY_BUF.with(|key| {
        let compute_key = |c, key: &mut CryptoVec, len| -> Result<(), crate::Error> {
            let mut buffer = buffer.borrow_mut();
            buffer.clear();
            key.clear();

            if let Some(ref shared) = self.shared_secret {
                buffer.extend_ssh_mpint(&shared.0);
            }

            buffer.extend(exchange_hash.as_ref());
            buffer.push(c);
            buffer.extend(session_id.as_ref());
            use openssl::hash::*;
            let hash = {
                let mut hasher = Hasher::new(MessageDigest::sha256())?;
                hasher.update(&buffer)?;
                hasher.finish()?
            };
            key.extend(hash.as_ref());

            while key.len() < len {
                // extend.
                buffer.clear();
                if let Some(ref shared) = self.shared_secret {
                    buffer.extend_ssh_mpint(&shared.0);
                }
                buffer.extend(exchange_hash.as_ref());
                buffer.extend(key);
                let hash = {
                    let mut hasher = Hasher::new(MessageDigest::sha256())?;
                    hasher.update(&buffer)?;
                    hasher.finish()?
                };
                key.extend(&hash.as_ref());
            }
            Ok(())
        };

        let (l_to_r_iv, l_to_r_key, l_to_r_mac, r_to_l_iv, r_to_l_key, r_to_l_mac) =
        if is_server {
            (b'B', b'D', b'F', b'A', b'C', b'E')
        } else {
            (b'A', b'C', b'E', b'B', b'D', b'F')
        };

        let mut iv = CryptoVec::new();
        let mut mac_key_l_to_r: [u8; 32] = [0; 32];
        let mut mac_key_r_to_l: [u8; 32] = [0; 32];
        let mut key = key.borrow_mut();
        if let Some(iv_len) = cipher.iv_len {
            compute_key(l_to_r_iv, &mut iv, iv_len)?;
        }
        compute_key(l_to_r_key, &mut key, cipher.key_len)?;
        let local_to_remote = (cipher.make_sealing_cipher)(&key, cipher.iv_len.map(|_| iv.as_ref()));
        compute_key(l_to_r_mac, &mut key, mac.key_len)?;
        mac_key_l_to_r.clone_from_slice(&key);
        let local_to_remote_mac = (mac.make_integrity_key_sign)(&key);

        if let Some(iv_len) = cipher.iv_len {
            compute_key(r_to_l_iv, &mut iv, iv_len)?;
        }
        compute_key(r_to_l_key, &mut key, cipher.key_len)?;
        let remote_to_local = (cipher.make_opening_cipher)(&key, cipher.iv_len.map(|_| iv.as_ref()));
        compute_key(r_to_l_mac, &mut key, mac.key_len)?;
        mac_key_r_to_l.clone_from_slice(&key);
        let remote_to_local_mac = (mac.make_integrity_key_verify)(&key);

        debug!("cipher l to r; {:?}", &local_to_remote);
        debug!("cipher r to l; {:?}", &remote_to_local);

        Ok((super::cipher::CipherPair {
            local_to_remote,
            remote_to_local,
        }, super::mac::MacPair {
            local_to_remote: super::mac::HMacAlgo::HmacSha256(mac_key_l_to_r, local_to_remote_mac),
            remote_to_local: super::mac::HMacAlgo::HmacSha256(mac_key_r_to_l, remote_to_local_mac),
        }))
        })
    })
    }
}
