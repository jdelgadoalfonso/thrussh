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

use super::super::Error;
use sodium::aes_128_ctr::{
    Aes128Ctr, NewCipher, StreamCipher, StreamCipherSeek,
    GenericArray, KEY_BYTES, NONCE_BYTES, Nonce, Key,
};

#[allow(dead_code)]
pub struct OpeningKey {
    iv: Nonce,
    key: Key,
    aes128_ctr: Aes128Ctr,
}

#[allow(dead_code)]
pub struct SealingKey {
    iv: Nonce,
    key: Key,
    aes128_ctr: Aes128Ctr,
}

const TAG_LEN: usize = 0;
const BLOCK_SIZE: usize = 16;

pub static CIPHER: super::Cipher = super::Cipher {
    name: NAME,
    key_len: 32,
    iv_len: Some(16),
    make_sealing_cipher,
    make_opening_cipher,
};

pub const NAME: super::Name = super::Name("aes128-ctr");

fn make_sealing_cipher(k: &[u8], i: Option<&[u8]>) -> super::SealingCipher {
    let mut iv = Nonce([0; NONCE_BYTES]);
    let mut key = Key([0; KEY_BYTES]);
    iv.0.clone_from_slice(&i.unwrap()[..NONCE_BYTES]);
    key.0.clone_from_slice(&k[..KEY_BYTES]);
    let g_key = GenericArray::from_slice(&key.0);
    let g_nonce = GenericArray::from_slice(&iv.0);
    // create cipher instance
    let cipher = Aes128Ctr::new(&g_key, &g_nonce);
    super::SealingCipher::Aes128Ctr(SealingKey {
        iv, key, aes128_ctr: cipher
    })
}

fn make_opening_cipher(k: &[u8], i: Option<&[u8]>) -> super::OpeningCipher {
    let mut iv = Nonce([0; NONCE_BYTES]);
    let mut key = Key([0; KEY_BYTES]);
    iv.0.clone_from_slice(&i.unwrap()[..NONCE_BYTES]);
    key.0.clone_from_slice(&k[..KEY_BYTES]);
    let g_key = GenericArray::from_slice(&key.0);
    let g_nonce = GenericArray::from_slice(&iv.0);
    // create cipher instance
    let cipher = Aes128Ctr::new(&g_key, &g_nonce);
    super::OpeningCipher::Aes128Ctr(OpeningKey {
        iv, key, aes128_ctr: cipher
    })
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &mut self,
        _sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        let pos: u64 = self.aes128_ctr.current_pos();
        //let mut p = self.aes128_ctr.clone();
        // p.apply_keystream(&mut encrypted_packet_length);
        self.aes128_ctr.apply_keystream(&mut encrypted_packet_length);
        self.aes128_ctr.seek(pos);
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        _tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        // self.sodium.apply_aes128ctr(&mut ciphertext_in_plaintext_out[..], &self.iv, &self.key);
        self.aes128_ctr.apply_keystream(ciphertext_in_plaintext_out);
        Ok(&ciphertext_in_plaintext_out[4..])
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - extra_len
        } else {
            BLOCK_SIZE - ((extra_len + payload.len()) % BLOCK_SIZE)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + BLOCK_SIZE
        } else {
            padding_len
        }
    }

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// Append an encrypted packet with contents `packet_content` at the end of `buffer`.
    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        _tag_out: &mut [u8],
    ) {
        debug!("sequence_number: {}", sequence_number);
        debug!("iv: {:?}", &self.iv.0);
        self.aes128_ctr.apply_keystream(plaintext_in_ciphertext_out);
    }
}
