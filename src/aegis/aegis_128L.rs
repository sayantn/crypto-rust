use crate::aegis::{aegis_impl, CONST_0, CONST_1};
use aes_crypto::AesBlock;

pub const KEY_LEN: usize = 16;
pub const IV_LEN: usize = 16;
pub const MAX_TAG_LEN: usize = 16;

type State = [AesBlock; 8];

fn state_update(state: &mut State, m0: AesBlock, m1: AesBlock) {
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
    let const_0 = AesBlock::from(CONST_0);
    let const_1 = AesBlock::from(CONST_1);

    let key = AesBlock::from(key);
    let iv = AesBlock::from(iv);

    let mut state = [
        key ^ iv,
        const_1,
        const_0,
        const_1,
        key ^ iv,
        key ^ const_0,
        key ^ const_1,
        key ^ const_0,
    ];

    for _ in -10..0 {
        state_update(&mut state, iv, key);
    }

    state
}

fn ingest_one_block(state: &mut State, aad: &[u8; 32]) {
    let a0 = AesBlock::try_from(&aad[..16]).unwrap();
    let a1 = AesBlock::try_from(&aad[16..]).unwrap();

    state_update(state, a0, a1);
}

fn encrypt_one_block(state: &mut State, plaintext: &[u8; 32], ciphertext: &mut [u8; 32]) {
    let p0 = AesBlock::try_from(&plaintext[..16]).unwrap();
    let p1 = AesBlock::try_from(&plaintext[16..]).unwrap();

    (p0 ^ state[1] ^ state[6] ^ (state[2] & state[3])).store_to(&mut ciphertext[..16]);
    (p1 ^ state[2] ^ state[5] ^ (state[6] & state[7])).store_to(&mut ciphertext[16..]);

    state_update(state, p0, p1);
}

fn decrypt_one_block(state: &mut State, ciphertext: &[u8; 32], plaintext: &mut [u8; 32]) {
    let c0 = AesBlock::try_from(&ciphertext[..16]).unwrap();
    let c1 = AesBlock::try_from(&ciphertext[16..]).unwrap();

    let p0 = c0 ^ state[1] ^ state[6] ^ (state[2] & state[3]);
    let p1 = c1 ^ state[2] ^ state[5] ^ (state[6] & state[7]);

    p0.store_to(&mut plaintext[..16]);
    p1.store_to(&mut plaintext[16..]);

    state_update(state, p0, p1);
}

fn decrypt_last_block(state: &mut State, ciphertext: &[u8], position: usize) -> [u8; 32] {
    let mut temp = [0; 32];
    temp[..position].copy_from_slice(ciphertext);

    let c0 = AesBlock::try_from(&ciphertext[..16]).unwrap();
    let c1 = AesBlock::try_from(&ciphertext[16..]).unwrap();

    let p0 = c0 ^ state[1] ^ state[6] ^ (state[2] & state[3]);
    let p1 = c1 ^ state[2] ^ state[5] ^ (state[6] & state[7]);

    p0.store_to(&mut temp[..16]);
    p1.store_to(&mut temp[16..]);

    temp[position..].fill(0);

    let p0 = AesBlock::try_from(&temp[..16]).unwrap();
    let p1 = AesBlock::try_from(&temp[16..]).unwrap();

    state_update(state, p0, p1);

    temp
}

fn finalize_state(mut state: State, aad_len: u64, msg_len: u64) -> [u8; MAX_TAG_LEN] {
    let tmp =
        state[2] ^ AesBlock::from(((aad_len.to_be() as u128) << 64) | (msg_len.to_be() as u128));

    for _ in 0..7 {
        state_update(&mut state, tmp, tmp);
    }

    (state[0] ^ state[1] ^ state[2] ^ state[3] ^ state[4] ^ state[5] ^ state[6] ^ state[7]).into()
}

aegis_impl!(Aegis128LEnc, Aegis128LDec, 32);
