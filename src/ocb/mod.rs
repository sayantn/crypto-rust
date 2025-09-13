use aes_crypto::{Aes128Enc, Aes192Enc, Aes256Enc, AesBlock, AesEncrypt};

pub mod aes128ocb;
pub mod aes192ocb;
pub mod aes256ocb;

fn double(s: AesBlock) -> AesBlock {
    let integer = u128::from(s);
    let mask = if integer & (1 << 127) == 0 { 0 } else { 0x87 };
    ((integer << 1) & mask).into()
}

#[derive(Debug, Clone)]
struct ExpandedKey {
    last_offset: AesBlock,
    tag_offset: AesBlock,
    offsets: [AesBlock; 32],
}

fn expand_128(key: [u8; 16]) -> (ExpandedKey, Aes128Enc) {
    let enc = Aes128Enc::from(key);
    (
        expand_key_internal(enc.encrypt_block(AesBlock::zero())),
        enc,
    )
}
fn expand_192(key: [u8; 24]) -> (ExpandedKey, Aes192Enc) {
    let enc = Aes192Enc::from(key);
    (
        expand_key_internal(enc.encrypt_block(AesBlock::zero())),
        enc,
    )
}
fn expand_256(key: [u8; 32]) -> (ExpandedKey, Aes256Enc) {
    let enc = Aes256Enc::from(key);
    (
        expand_key_internal(enc.encrypt_block(AesBlock::zero())),
        enc,
    )
}

fn expand_key_internal(last_offset: AesBlock) -> ExpandedKey {
    let tag_offset = double(last_offset);
    let mut offsets = [AesBlock::default(); 32];
    offsets[0] = double(tag_offset);
    for i in 1..32 {
        offsets[i] = double(offsets[i - 1]);
    }
    ExpandedKey {
        last_offset,
        tag_offset,
        offsets,
    }
}

macro_rules! starting_offset {
    ($enc:expr, $n:ident) => {{
        let mut nonce = [0u8; 16];
        nonce[0] = 128;
        let n_len = std::cmp::min($n.len(), 15);
        nonce[16 - n_len..].copy_from_slice(&$n[..n_len]);
        nonce[15 - n_len] |= 0x01;

        let bottom = nonce[15] & 0x3f;

        nonce[15] &= 0xc0;
        let k_top: u128 = $enc.encrypt_block(nonce.into()).into();

        let stretch = (k_top >> 64) ^ ((k_top >> 56) & 0xffffffffffffffff);

        ((k_top << bottom) | (stretch >> (64 - bottom))).into()
    }};
}

use starting_offset;

macro_rules! ocb_impl {
    ($enc_name:ident, $dec_name:ident, $aes_enc:ty, $expand:ident) => {
        use aes_crypto::{AesBlock, AesEncrypt};
        use $crate::buffer::Buffer;
        use $crate::ocb::{starting_offset, $expand, ExpandedKey};

        #[derive(Debug)]
        pub struct $enc_name {
            key: ExpandedKey,
            enc: $aes_enc,

            ingest_buffer: Buffer<16>,
            ingest_offset: AesBlock,
            ingest_counter: u64,
            sum: AesBlock,

            wrap_buffer: Buffer<16>,
            wrap_offset: AesBlock,
            wrap_counter: u64,
            checksum: AesBlock,
        }

        #[derive(Debug)]
        pub struct $dec_name {
            key: ExpandedKey,
            enc: $aes_enc,

            ingest_buffer: Buffer<16>,
            ingest_offset: AesBlock,
            ingest_counter: u64,
            sum: AesBlock,

            wrap_buffer: Buffer<16>,
            wrap_offset: AesBlock,
            wrap_counter: u64,
            checksum: AesBlock,
        }

        impl $crate::Encrypt<KEY_LEN, 15> for $enc_name {
            fn new(key: [u8; KEY_LEN], iv: [u8; 15]) -> Self {
                let (key, enc) = $expand(key);
                let wrap_offset = starting_offset!(enc, iv);
                Self {
                    key,
                    enc,
                    ingest_buffer: Buffer::new(),
                    ingest_offset: AesBlock::zero(),
                    ingest_counter: 1,
                    sum: AesBlock::zero(),
                    wrap_buffer: Buffer::new(),
                    wrap_offset,
                    wrap_counter: 1,
                    checksum: AesBlock::zero(),
                }
            }

            fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> usize {
                self.wrap_buffer
                    .transform_blocks::<false>(plaintext, ciphertext, |pt, ct| {
                        self.wrap_offset ^=
                            self.key.offsets[self.wrap_counter.trailing_zeros() as usize];
                        let p = AesBlock::from(pt);
                        (self.wrap_offset ^ self.enc.encrypt_block(p ^ self.wrap_offset))
                            .store_to(ct);
                        self.checksum ^= p;
                        self.wrap_counter += 1;
                    })
            }
        }

        impl $crate::Ingest for $enc_name {
            fn ingest(&mut self, aad: &[u8]) {
                self.ingest_buffer.process_blocks::<false>(aad, |block| {
                    self.ingest_offset ^=
                        self.key.offsets[self.ingest_counter.trailing_zeros() as usize];
                    self.sum ^= self
                        .enc
                        .encrypt_block(AesBlock::from(block) ^ self.ingest_offset);
                    self.ingest_counter += 1;
                })
            }
        }

        impl $crate::AuthenticatedEncrypt<KEY_LEN, 15, 16> for $enc_name {
            fn finish(mut self, ciphertext: &mut [u8]) -> (usize, [u8; 16]) {
                if !self.ingest_buffer.is_empty() {
                    self.ingest_offset ^= self.key.last_offset;

                    self.ingest_buffer.append_byte(0x80);
                    let block = AesBlock::from(self.ingest_buffer.pad_zero());

                    self.sum ^= self.enc.encrypt_block(block ^ self.ingest_offset);
                }

                let ret = if !self.wrap_buffer.is_empty() {
                    let position = self.wrap_buffer.position();

                    self.wrap_offset ^= self.key.last_offset;

                    self.wrap_buffer.append_byte(0x80);
                    let p = AesBlock::from(self.wrap_buffer.pad_zero());

                    self.checksum ^= p;
                    let temp = (p ^ self.enc.encrypt_block(self.wrap_offset)).to_bytes();

                    ciphertext[..position].copy_from_slice(&temp[..position]);

                    position
                } else {
                    0
                };

                let checksum = self
                    .enc
                    .encrypt_block(self.checksum ^ self.wrap_offset ^ self.key.tag_offset);

                (ret, (checksum ^ self.sum).into())
            }
        }

        impl $crate::Decrypt<KEY_LEN, 15> for $dec_name {
            fn new(key: [u8; KEY_LEN], iv: [u8; 15]) -> Self {
                let (key, enc) = $expand(key);
                let wrap_offset = starting_offset!(enc, iv);
                Self {
                    key,
                    enc,
                    ingest_buffer: Buffer::new(),
                    ingest_offset: AesBlock::zero(),
                    ingest_counter: 1,
                    sum: AesBlock::zero(),
                    wrap_buffer: Buffer::new(),
                    wrap_offset,
                    wrap_counter: 1,
                    checksum: AesBlock::zero(),
                }
            }

            fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> usize {
                self.wrap_buffer
                    .transform_blocks::<false>(ciphertext, plaintext, |ct, pt| {
                        self.wrap_offset ^=
                            self.key.offsets[self.wrap_counter.trailing_zeros() as usize];
                        let p = self.wrap_offset
                            ^ self
                                .enc
                                .encrypt_block(AesBlock::from(ct) ^ self.wrap_offset);
                        p.store_to(pt);
                        self.checksum ^= p;
                        self.wrap_counter += 1;
                    })
            }
        }

        impl $crate::Ingest for $dec_name {
            fn ingest(&mut self, aad: &[u8]) {
                self.ingest_buffer.process_blocks::<false>(aad, |block| {
                    self.ingest_offset ^=
                        self.key.offsets[self.ingest_counter.trailing_zeros() as usize];
                    self.sum ^= self
                        .enc
                        .encrypt_block(AesBlock::from(block) ^ self.ingest_offset);
                    self.ingest_counter += 1;
                })
            }
        }

        impl $crate::AuthenticatedDecrypt<KEY_LEN, 15, 16> for $dec_name {
            fn finish(mut self, plaintext: &mut [u8], tag: &[u8]) -> Result<usize, ()> {
                if !self.ingest_buffer.is_empty() {
                    self.ingest_offset ^= self.key.last_offset;

                    self.ingest_buffer.append_byte(0x80);
                    let block = AesBlock::from(self.ingest_buffer.pad_zero());

                    self.sum ^= self.enc.encrypt_block(block ^ self.ingest_offset);
                }

                let ret = if !self.wrap_buffer.is_empty() {
                    let position = self.wrap_buffer.position();

                    self.wrap_offset ^= self.key.last_offset;

                    let mut temp: [u8; 16] = (AesBlock::from(self.wrap_buffer.pad_zero())
                        ^ self.enc.encrypt_block(self.wrap_offset))
                    .into();

                    temp[position] = 0x80;
                    temp[position + 1..].fill(0);

                    self.checksum ^= temp.into();

                    plaintext[..position].copy_from_slice(&temp[..position]);

                    position
                } else {
                    0
                };

                let checksum = self
                    .enc
                    .encrypt_block(self.checksum ^ self.wrap_offset ^ self.key.tag_offset);

                if $crate::ct_eq(tag, &checksum.to_bytes()) {
                    Ok(ret)
                } else {
                    Err(())
                }
            }
        }
    };
}

use ocb_impl;
