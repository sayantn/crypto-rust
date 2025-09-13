use crate::aegis::{aegis_impl, CONST_0, CONST_1};
use aes_crypto::AesBlock;

pub const KEY_LEN: usize = 16;
pub const IV_LEN: usize = 16;
pub const MAX_TAG_LEN: usize = 16;

type State = [AesBlock; 5];

fn state_update(state: &mut State, m: AesBlock) {
    let temp = state[4];

    state[4] = state[3].enc(state[4]);
    state[3] = state[2].enc(state[3]);
    state[2] = state[1].enc(state[2]);
    state[1] = state[0].enc(state[1]);
    state[0] = temp.enc(state[0] ^ m);
}

fn initialize(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> State {
    let key = AesBlock::from(key);
    let iv = AesBlock::from(iv);

    let kn = key ^ iv;

    let mut state = [kn, CONST_1, CONST_0, key ^ CONST_0, iv ^ CONST_1];

    for _ in 0..5 {
        state_update(&mut state, key);
        state_update(&mut state, kn);
    }

    state
}

fn ingest_one_block(state: &mut State, aad: &[u8; 16]) {
    state_update(state, aad.into());
}

fn encrypt_one_block(state: &mut State, plaintext: &[u8; 16], ciphertext: &mut [u8; 16]) {
    let p = AesBlock::from(plaintext);
    (p ^ state[1] ^ state[4] ^ (state[2] & state[3])).store_to(ciphertext);
    state_update(state, p);
}

fn decrypt_one_block(state: &mut State, ciphertext: &[u8; 16], plaintext: &mut [u8; 16]) {
    let p = AesBlock::from(ciphertext) ^ state[1] ^ state[4] ^ (state[2] & state[3]);
    p.store_to(plaintext);
    state_update(state, p);
}

fn decrypt_last_block(state: &mut State, ciphertext: &[u8], position: usize) -> [u8; 16] {
    let mut temp = [0; 16];
    temp[..position].copy_from_slice(ciphertext);

    (AesBlock::from(temp) ^ state[1] ^ state[4] ^ (state[2] & state[3])).store_to(&mut temp);

    temp[position..].fill(0);

    let p = AesBlock::from(temp);

    state_update(state, p);

    temp
}

fn finalize_state(mut state: State, aad_len: u64, msg_len: u64) -> [u8; MAX_TAG_LEN] {
    let tmp = state[3]
        ^ AesBlock::from((u128::from(aad_len.to_be()) << 64) | u128::from(msg_len.to_be()));

    for _ in 0..7 {
        state_update(&mut state, tmp);
    }

    (state[0] ^ state[1] ^ state[2] ^ state[3] ^ state[4]).into()
}

aegis_impl!(Aegis128Enc, Aegis128Dec, 16);
