pub const KEY_LEN: usize = 16;
pub const IV_LEN: usize = 15;
pub const MAX_TAG_LEN: usize = 16;

super::ocb_impl!(
    Aes128OcbEnc,
    Aes128OcbDec,
    aes_crypto::Aes128Enc,
    expand_128
);
