pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 15;
pub const MAX_TAG_LEN: usize = 16;

super::ocb_impl!(
    Aes256OcbEnc,
    Aes256OcbDec,
    aes_crypto::Aes256Enc,
    expand_256
);
