#![allow(non_snake_case)]

use aes_crypto::{AesBlock, AesBlockX2, AesBlockX4};

pub mod aegis_128;
pub mod aegis_128L;
pub mod aegis_128X2;
pub mod aegis_128X4;
pub mod aegis_256;
pub mod aegis_256X2;
pub mod aegis_256X4;

const CONST_0: AesBlock = AesBlock::new([
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
]);

const CONST_1: AesBlock = AesBlock::new([
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
]);

const AEGIS_X2_CTX: AesBlockX2 = AesBlockX2::new([
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

const AEGIS_X4_CTX: AesBlockX4 = AesBlockX4::new([
    0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

macro_rules! aegis_impl {
    ($enc_name: ident, $dec_name: ident, $buf_size:literal) => {
        #[derive(Debug)]
        pub struct $enc_name {
            stage: $crate::Stage,
            state: State,
            buffer: $crate::buffer::Buffer<$buf_size>,
            aad_len: u64,
            msg_len: u64,
        }

        impl $crate::Encrypt<KEY_LEN, IV_LEN> for $enc_name {
            fn new(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> Self {
                Self {
                    stage: $crate::Stage::Ingesting,
                    state: initialize(key, iv),
                    buffer: $crate::buffer::Buffer::new(),
                    aad_len: 0,
                    msg_len: 0,
                }
            }

            fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> usize {
                if self.stage == $crate::Stage::Ingesting {
                    if !self.buffer.is_empty() {
                        ingest_one_block(&mut self.state, self.buffer.pad_zero());
                        self.buffer.reset()
                    }
                    self.stage = $crate::Stage::Wrapping;
                }

                assert!(
                    ciphertext.len()
                        >= (plaintext.len() + self.buffer.position()) & !($buf_size - 1)
                );

                self.msg_len += 8 * plaintext.len() as u64;

                self.buffer
                    .transform_blocks::<false>(plaintext, ciphertext, |pt, ct| {
                        encrypt_one_block(&mut self.state, pt, ct)
                    })
            }
        }

        impl $crate::Ingest for $enc_name {
            fn ingest(&mut self, aad: &[u8]) {
                assert_eq!(self.stage, $crate::Stage::Ingesting);

                self.aad_len += 8 * aad.len() as u64;

                self.buffer
                    .process_blocks::<false>(aad, |chunk| ingest_one_block(&mut self.state, chunk));
            }
        }

        impl $crate::AuthenticatedEncrypt<KEY_LEN, IV_LEN, 16> for $enc_name {
            fn finish(mut self, ciphertext: &mut [u8]) -> (usize, [u8; 16]) {
                let ret = match self.stage {
                    $crate::Stage::Ingesting => {
                        if !self.buffer.is_empty() {
                            ingest_one_block(&mut self.state, self.buffer.pad_zero());
                        }
                        0
                    }
                    $crate::Stage::Wrapping => {
                        if !self.buffer.is_empty() {
                            let position = self.buffer.position();
                            assert!(ciphertext.len() >= position);

                            let mut temp = [0; $buf_size];
                            encrypt_one_block(&mut self.state, &self.buffer.pad_zero(), &mut temp);
                            ciphertext[..position].copy_from_slice(&temp[..position]);
                            position
                        } else {
                            0
                        }
                    }
                };

                (ret, finalize_state(self.state, self.aad_len, self.msg_len))
            }
        }

        #[derive(Debug)]
        pub struct $dec_name {
            stage: $crate::Stage,
            state: State,
            buffer: $crate::buffer::Buffer<$buf_size>,
            aad_len: u64,
            msg_len: u64,
        }

        impl $crate::Decrypt<KEY_LEN, IV_LEN> for $dec_name {
            fn new(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> Self {
                Self {
                    stage: $crate::Stage::Ingesting,
                    state: initialize(key, iv),
                    buffer: $crate::buffer::Buffer::new(),
                    aad_len: 0,
                    msg_len: 0,
                }
            }
            fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> usize {
                if self.stage == $crate::Stage::Ingesting {
                    if !self.buffer.is_empty() {
                        ingest_one_block(&mut self.state, self.buffer.pad_zero());
                        self.buffer.reset();
                    }
                    self.stage = $crate::Stage::Wrapping;
                }

                assert!(
                    plaintext.len()
                        >= (ciphertext.len() + self.buffer.position()) & !($buf_size - 1)
                );

                self.msg_len += 8 * ciphertext.len() as u64;

                self.buffer
                    .transform_blocks::<false>(ciphertext, plaintext, |ct, pt| {
                        decrypt_one_block(&mut self.state, ct, pt)
                    })
            }
        }

        impl $crate::Ingest for $dec_name {
            fn ingest(&mut self, aad: &[u8]) {
                assert_eq!(self.stage, $crate::Stage::Ingesting);

                self.aad_len += 8 * aad.len() as u64;

                self.buffer
                    .process_blocks::<false>(aad, |chunk| ingest_one_block(&mut self.state, chunk));
            }
        }

        impl $crate::AuthenticatedDecrypt<KEY_LEN, IV_LEN, 16> for $dec_name {
            fn finish(mut self, plaintext: &mut [u8], tag: &[u8]) -> Result<usize, ()> {
                let ret = match self.stage {
                    $crate::Stage::Ingesting => {
                        if !self.buffer.is_empty() {
                            ingest_one_block(&mut self.state, self.buffer.pad_zero());
                        }
                        0
                    }
                    $crate::Stage::Wrapping => {
                        if !self.buffer.is_empty() {
                            let position = self.buffer.position();
                            assert!(plaintext.len() >= position);

                            let temp =
                                decrypt_last_block(&mut self.state, self.buffer.as_ref(), position);

                            plaintext[..position].copy_from_slice(&temp[..position]);
                            position
                        } else {
                            0
                        }
                    }
                };

                let expected = finalize_state(self.state, self.aad_len, self.msg_len);

                if $crate::ct_eq(&expected, tag) {
                    Ok(ret)
                } else {
                    Err(())
                }
            }
        }
    };
}

use aegis_impl;
