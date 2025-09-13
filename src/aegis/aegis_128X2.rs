use crate::aegis::{aegis_impl, AEGIS_X2_CTX, CONST_0, CONST_1};
use aes_crypto::{AesBlock, AesBlockX2};

pub const KEY_LEN: usize = 16;
pub const IV_LEN: usize = 16;
pub const MAX_TAG_LEN: usize = 16;

type State = [AesBlockX2; 8];

fn state_update(state: &mut State, m0: AesBlockX2, m1: AesBlockX2) {
    let temp = state[7];

    state[7] = state[6].enc(state[7]);
    state[6] = state[5].enc(state[6]);
    state[5] = state[4].enc(state[5]);
    state[4] = state[3].enc(state[4] ^ m1);
    state[3] = state[2].enc(state[3]);
    state[2] = state[1].enc(state[2]);
    state[1] = state[0].enc(state[1]);
    state[0] = temp.enc(state[0] ^ m0);
}

fn initialize(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> State {
    let key = AesBlock::from(key);
    let iv = AesBlock::from(iv);

    let mut state = [
        (key ^ iv).into(),
        CONST_1.into(),
        CONST_0.into(),
        CONST_1.into(),
        (key ^ iv).into(),
        (key ^ CONST_0).into(),
        (key ^ CONST_1).into(),
        (key ^ CONST_0).into(),
    ];

    let key = key.into();
    let iv = iv.into();

    for _ in 0..10 {
        state[3] ^= AEGIS_X2_CTX;
        state[7] ^= AEGIS_X2_CTX;
        state_update(&mut state, iv, key);
    }

    state
}

fn ingest_one_block(state: &mut State, aad: &[u8; 64]) {
    let a0 = AesBlockX2::try_from(&aad[..32]).unwrap();
    let a1 = AesBlockX2::try_from(&aad[32..]).unwrap();

    state_update(state, a0, a1);
}

fn encrypt_one_block(state: &mut State, plaintext: &[u8; 64], ciphertext: &mut [u8; 64]) {
    let p0 = AesBlockX2::try_from(&plaintext[..32]).unwrap();
    let p1 = AesBlockX2::try_from(&plaintext[32..]).unwrap();

    (p0 ^ state[1] ^ state[6] ^ (state[2] & state[3])).store_to(&mut ciphertext[..32]);
    (p1 ^ state[2] ^ state[5] ^ (state[6] & state[7])).store_to(&mut ciphertext[32..]);

    state_update(state, p0, p1);
}

fn decrypt_one_block(state: &mut State, ciphertext: &[u8; 64], plaintext: &mut [u8; 64]) {
    let c0 = AesBlockX2::try_from(&ciphertext[..32]).unwrap();
    let c1 = AesBlockX2::try_from(&ciphertext[32..]).unwrap();

    let p0 = c0 ^ state[1] ^ state[6] ^ (state[2] & state[3]);
    let p1 = c1 ^ state[2] ^ state[5] ^ (state[6] & state[7]);

    p0.store_to(&mut plaintext[..32]);
    p1.store_to(&mut plaintext[32..]);

    state_update(state, p0, p1);
}

fn decrypt_last_block(state: &mut State, ciphertext: &[u8], position: usize) -> [u8; 64] {
    let mut temp = [0; 64];
    temp[..position].copy_from_slice(ciphertext);

    let c0 = AesBlockX2::try_from(&ciphertext[..32]).unwrap();
    let c1 = AesBlockX2::try_from(&ciphertext[32..]).unwrap();

    let p0 = c0 ^ state[1] ^ state[6] ^ (state[2] & state[3]);
    let p1 = c1 ^ state[2] ^ state[5] ^ (state[6] & state[7]);

    p0.store_to(&mut temp[..32]);
    p1.store_to(&mut temp[32..]);

    temp[position..].fill(0);

    let p0 = AesBlockX2::try_from(&temp[..32]).unwrap();
    let p1 = AesBlockX2::try_from(&temp[32..]).unwrap();

    state_update(state, p0, p1);

    temp
}

fn finalize_state(mut state: State, aad_len: u64, msg_len: u64) -> [u8; MAX_TAG_LEN] {
    let tmp = state[2]
        ^ AesBlock::from((u128::from(aad_len.to_be()) << 64) | u128::from(msg_len.to_be())).into();

    for _ in 0..7 {
        state_update(&mut state, tmp, tmp);
    }

    let (tag0, tag1) =
        (state[0] ^ state[1] ^ state[2] ^ state[3] ^ state[4] ^ state[5] ^ state[6] ^ state[7])
            .into();
    (tag0 ^ tag1).into()
}

aegis_impl!(Aegis128X2Enc, Aegis128X2Dec, 64);
