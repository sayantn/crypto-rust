use std::iter::zip;

pub mod aegis;
pub mod buffer;
pub mod ocb;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
enum Stage {
    #[default]
    Ingesting,
    Wrapping,
}

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    zip(a, b).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub trait Encrypt<const KEY_LEN: usize, const IV_LEN: usize> {
    fn new(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> Self
    where
        Self: Sized;

    fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> usize;
}

pub trait Decrypt<const KEY_LEN: usize, const IV_LEN: usize> {
    fn new(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> Self
    where
        Self: Sized;

    fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> usize;
}

pub trait Ingest {
    fn ingest(&mut self, data: &[u8]);
}

pub trait AuthenticatedEncrypt<const KEY_LEN: usize, const IV_LEN: usize, const TAG_LEN: usize>:
    Encrypt<KEY_LEN, IV_LEN> + Ingest
{
    fn finish(self, ciphertext: &mut [u8]) -> (usize, [u8; TAG_LEN]);
}

pub trait AuthenticatedDecrypt<const KEY_LEN: usize, const IV_LEN: usize, const TAG_LEN: usize>:
    Decrypt<KEY_LEN, IV_LEN> + Ingest
{
    fn finish(self, plaintext: &mut [u8], tag: &[u8]) -> Result<usize, ()>;
}

pub trait Digest<const DIGEST_LEN: usize>: Ingest {
    fn new() -> Self
    where
        Self: Sized;

    fn digest(self) -> [u8; DIGEST_LEN];
}

pub trait Authenticate<const KEY_LEN: usize, const TAG_LEN: usize>: Ingest {
    fn new(key: [u8; KEY_LEN]) -> Self
    where
        Self: Sized;

    fn authenticate(self) -> [u8; TAG_LEN];

    #[must_use]
    fn verify(self, tag: &[u8]) -> bool;
}
