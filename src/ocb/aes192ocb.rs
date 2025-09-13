pub const KEY_LEN: usize = 24;
pub const IV_LEN: usize = 15;
pub const MAX_TAG_LEN: usize = 16;

super::ocb_impl!(
    Aes192OcbEnc,
    Aes192OcbDec,
    aes_crypto::Aes192Enc,
    expand_192
);
