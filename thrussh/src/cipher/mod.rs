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
use byteorder::{ByteOrder, BigEndian};
use Error;
use std;
use sshbuffer::SSHBuffer;
use std::num::Wrapping;
use tokio::io::AsyncRead;
use read_exact_from::*;
use futures::{Future, Async, Poll};
use std::sync::{Arc, Mutex};
use cryptovec::CryptoVec;
use mac::MacPair;

pub mod chacha20poly1305;
pub mod aes128ctr;
pub mod clear;

pub struct Cipher {
    pub name: Name,
    pub key_len: usize,
    pub iv_len: Option<usize>,
    pub make_opening_cipher: fn(key: &[u8], iv: Option<&[u8]>) -> OpeningCipher,
    pub make_sealing_cipher: fn(key: &[u8], iv: Option<&[u8]>) -> SealingCipher,
}

pub enum OpeningCipher {
    Clear(clear::Key),
    Chacha20Poly1305(chacha20poly1305::OpeningKey),
    Aes128Ctr(aes128ctr::OpeningKey),
}

impl<'a> OpeningCipher {
    fn as_opening_key(&'a mut self) -> &'a mut dyn OpeningKey {
        match *self {
            OpeningCipher::Clear(ref mut key) => key,
            OpeningCipher::Chacha20Poly1305(ref mut key) => key,
            OpeningCipher::Aes128Ctr(ref mut key) => key,
        }
    }
}

pub enum SealingCipher {
    Clear(clear::Key),
    Chacha20Poly1305(chacha20poly1305::SealingKey),
    Aes128Ctr(aes128ctr::SealingKey),
}

impl<'a> SealingCipher {
    fn as_sealing_key(&'a mut self) -> &'a mut dyn SealingKey {
        match *self {
            SealingCipher::Clear(ref mut key) => key,
            SealingCipher::Chacha20Poly1305(ref mut key) => key,
            SealingCipher::Aes128Ctr(ref mut key) => key,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

pub struct CipherPair {
    pub local_to_remote: SealingCipher,
    pub remote_to_local: OpeningCipher,
}

impl std::fmt::Debug for CipherPair {
    fn fmt(&self, _: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        Ok(()) // TODO?
    }
}

pub const CLEAR_PAIR: CipherPair = CipherPair {
    local_to_remote: SealingCipher::Clear(clear::Key),
    remote_to_local: OpeningCipher::Clear(clear::Key),
};

pub trait OpeningKey {

    fn decrypt_packet_length(&mut self, seqn: u32, encrypted_packet_length: [u8; 4]) -> [u8; 4];

    fn tag_len(&self) -> usize;

    fn open<'a>(
        &mut self,
        seqn: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error>;
}

pub trait SealingKey {

    fn padding_length(&self, plaintext: &[u8]) -> usize;

    fn fill_padding(&self, padding_out: &mut [u8]);

    fn tag_len(&self) -> usize;

    fn seal(&mut self, seqn: u32, plaintext_in_ciphertext_out: &mut [u8], tag_out: &mut [u8]);
}

enum CipherReadState<R: AsyncRead> {
    Len {
        len: ReadExact<R, [u8; 4]>,
        buffer: SSHBuffer,
        pair: Arc<Mutex<CipherPair>>,
        mac: Arc<MacPair>,
    },
    Body {
        body: ReadExact<R, CryptoVec>,
        buffer: SSHBuffer,
        pair: Arc<Mutex<CipherPair>>,
        mac: Arc<MacPair>,
    },
}

pub struct CipherRead<R: AsyncRead>(Option<CipherReadState<R>>);

impl<R: AsyncRead> CipherRead<R> {
    pub fn try_abort(&mut self) -> Option<(R, SSHBuffer)> {
        if let Some(CipherReadState::Len {
                        mut len,
                        buffer,
                        pair,
                        mac,
                    }) = self.0.take()
        {
            // Aborting, and abandoning the 4 bytes of buffer.
            if let Some((r, _)) = len.try_abort() {
                return Some((r, buffer));
            } else {
                self.0 = Some(CipherReadState::Len { len, buffer, pair, mac })
            }
        }
        None
    }
}

impl<R: AsyncRead> Future for CipherRead<R> {
    type Item = (R, SSHBuffer, usize);
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            debug!("cipherread poll");
            match self.0.take() {
                None => panic!("future is over"),
                Some(CipherReadState::Len {
                         mut len,
                         mut buffer,
                         pair,
                         mac,
                     }) => {
                    if let Async::Ready((stream, len_)) = len.poll()? {
                        {
                            let mut m_pair = pair.lock().unwrap();
                            let key = m_pair.remote_to_local.as_opening_key();
                            let seqn = buffer.seqn.0;
                            buffer.buffer.clear();
                            buffer.buffer.extend(&len_);
                            let len = key.decrypt_packet_length(seqn, len_);
                            let len = BigEndian::read_u32(&len) as usize + key.tag_len();
                            let mac_len = if let super::mac::HMacAlgo::HmacSha256(..) = mac.remote_to_local {
                                32 //32 bytes of mac
                            } else {
                                0
                            };
                            buffer.buffer.resize(len + 4 + mac_len);
                        }
                        self.0 = Some(CipherReadState::Body {
                            body: read_exact_from(
                                stream,
                                std::mem::replace(&mut buffer.buffer, CryptoVec::new()),
                                4,
                            ),
                            buffer,
                            pair,
                            mac,
                        })
                    } else {
                        self.0 = Some(CipherReadState::Len { len, buffer, pair, mac });
                        return Ok(Async::NotReady);
                    }
                }
                Some(CipherReadState::Body {
                         mut body,
                         mut buffer,
                         pair,
                         mac,
                     }) => {
                    if let Async::Ready((stream, body)) = body.poll()? {
                        let plaintext_end = {
                            buffer.buffer = body;
                            let mut m_pair = pair.lock().unwrap();
                            let key = m_pair.remote_to_local.as_opening_key();
                            let seqn = buffer.seqn.0;
                            let mac_len = if let super::mac::HMacAlgo::HmacSha256(..) = mac.remote_to_local {
                                32 //32 bytes of mac
                            } else {
                                0
                            };
                            let ciphertext_len = buffer.buffer.len() - key.tag_len() - mac_len;
                            let (ciphertext, tag_mac) = buffer.buffer.split_at_mut(ciphertext_len);
                            let (tag, _mac) = tag_mac.split_at_mut(key.tag_len()); // TODO: mac
                            let plaintext = key.open(seqn, ciphertext, tag)?;

                            let padding_length = plaintext[0] as usize;
                            let plaintext_end = plaintext.len().checked_sub(padding_length).ok_or(
                                Error::IndexOutOfBounds,
                            )?;

                            // Sequence numbers are on 32 bits and wrap.
                            // https://tools.ietf.org/html/rfc4253#section-6.4
                            buffer.seqn += Wrapping(1);
                            buffer.len = 0;

                            plaintext_end
                        };
                        return Ok(Async::Ready((stream, buffer, plaintext_end + 4)));
                    } else {
                        self.0 = Some(CipherReadState::Body { body, buffer, pair, mac });
                        return Ok(Async::NotReady);
                    }
                }
            }
        }
    }
}

pub fn read<R: AsyncRead>(
    stream: R, buffer: SSHBuffer, pair: Arc<Mutex<CipherPair>>, mac: Arc<MacPair>
) -> CipherRead<R> {
    CipherRead(Some(CipherReadState::Len {
        len: read_exact_from(stream, [0; 4], 0),
        buffer,
        pair,
        mac,
    }))
}

impl CipherPair {
    pub fn write(&mut self, payload: &[u8], buffer: &mut SSHBuffer, mac: &super::mac::MacPair) {
        // https://tools.ietf.org/html/rfc4253#section-6
        //
        // The variables `payload`, `packet_length` and `padding_length` refer
        // to the protocol fields of the same names.

        let key = self.local_to_remote.as_sealing_key();

        let padding_length = key.padding_length(payload);
        let packet_length = PADDING_LENGTH_LEN + payload.len() + padding_length;
        let offset = buffer.buffer.len();

        // Maximum packet length:
        // https://tools.ietf.org/html/rfc4253#section-6.1
        assert!(packet_length <= std::u32::MAX as usize);
        buffer.buffer.push_u32_be(packet_length as u32);

        debug!("CipherPair.write: Packet length: {}", packet_length as u32);
        debug!("CipherPair.write: Payload length: {}", payload.len());
        debug!("CipherPair.write: Padding length: {}", PADDING_LENGTH_LEN + padding_length);

        assert!(padding_length <= std::u8::MAX as usize);
        buffer.buffer.push(padding_length as u8);
        buffer.buffer.extend(payload);
        key.fill_padding(buffer.buffer.resize_mut(padding_length));
        buffer.buffer.resize_mut(key.tag_len());

        let (plaintext, tag) =
            buffer.buffer[offset..].split_at_mut(PACKET_LENGTH_LEN + packet_length);

        let mut tmp: Vec<u8> = Vec::new();
        tmp.extend_from_slice(plaintext);

        key.seal(buffer.seqn.0, plaintext, tag);

        let mut unenc_packet: CryptoVec = CryptoVec::new();
        unenc_packet.push_u32_be(buffer.seqn.0);
        unenc_packet.extend(&tmp);
        mac.sign(&unenc_packet, buffer);

        // Sequence numbers are on 32 bits and wrap.
        // https://tools.ietf.org/html/rfc4253#section-6.4
        buffer.seqn += Wrapping(1);
    }
}


pub const PACKET_LENGTH_LEN: usize = 4;

const MINIMUM_PACKET_LEN: usize = 16;

const PADDING_LENGTH_LEN: usize = 1;
