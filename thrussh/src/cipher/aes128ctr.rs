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

// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD

use super::super::Error;
use sodium::Sodium;
use sodium::aes_128_ctr::{KEY_BYTES, NONCE_BYTES, Nonce, Key};
use byteorder::{ByteOrder, BigEndian};

pub struct OpeningKey { k1: Key, k2: Key, sodium: Sodium }
pub struct SealingKey { k1: Key, k2: Key, sodium: Sodium }

const TAG_LEN: usize = 0;

pub static CIPHER: super::Cipher = super::Cipher {
    name: NAME,
    key_len: 32,
    make_sealing_cipher,
    make_opening_cipher,
};

pub const NAME: super::Name = super::Name("aes-128-ctr");

fn make_sealing_cipher(k: &[u8]) -> super::SealingCipher {
    let mut k1 = Key([0; KEY_BYTES]);
    let mut k2 = Key([0; KEY_BYTES]);
    k1.0.clone_from_slice(&k[KEY_BYTES..]);
    k2.0.clone_from_slice(&k[..KEY_BYTES]);
    super::SealingCipher::Aes128Ctr(SealingKey { k1, k2, sodium: Sodium::new() })
}

fn make_opening_cipher(k: &[u8]) -> super::OpeningCipher {
    let mut k1 = Key([0; KEY_BYTES]);
    let mut k2 = Key([0; KEY_BYTES]);
    k1.0.clone_from_slice(&k[KEY_BYTES..]);
    k2.0.clone_from_slice(&k[..KEY_BYTES]);
    super::OpeningCipher::Aes128Ctr(OpeningKey { k1, k2, sodium: Sodium::new() })
}

fn make_counter(sequence_number: u32) -> Nonce {
    let mut nonce = Nonce([0; NONCE_BYTES]);
    let i0 = NONCE_BYTES-4;
    BigEndian::write_u32(&mut nonce.0[i0..], sequence_number);
    nonce
}

impl super::OpeningKey for OpeningKey {

    fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        let nonce = make_counter(sequence_number);
        self.sodium.apply_aes128ctr(&mut encrypted_packet_length, &nonce, &self.k1);
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        _tag: &[u8],
    ) -> Result<&'a [u8], Error> {

        let nonce = make_counter(sequence_number);
        self.sodium.apply_aes128ctr(&mut ciphertext_in_plaintext_out[4..], &nonce, &self.k2);
        Ok(&ciphertext_in_plaintext_out[4..])
    }
}

impl super::SealingKey for SealingKey {

    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            (block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size))
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
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
        &self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        _tag_out: &mut [u8],
    ) {
        let nonce = make_counter(sequence_number);
        let (a, b) = plaintext_in_ciphertext_out.split_at_mut(4);
        self.sodium.apply_aes128ctr(a, &nonce, &self.k1);
        self.sodium.apply_aes128ctr(b, &nonce, &self.k2);
    }
}
