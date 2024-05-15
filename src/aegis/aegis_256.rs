use crate::aegis::{aegis_impl, CONST_0, CONST_1};
use aes_crypto::AesBlock;

pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 32;
pub const MAX_TAG_LEN: usize = 16;

type State = [AesBlock; 6];

fn state_update(state: &mut State, m: AesBlock) {
    let temp = state[5];

    state[5] = state[4].enc(state[5]);
    state[4] = state[3].enc(state[4]);
    state[3] = state[2].enc(state[3]);
    state[2] = state[1].enc(state[2]);
    state[1] = state[0].enc(state[1]);
    state[0] = temp.enc(state[0] ^ m);
}

fn initialize(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> State {
    let key0 = AesBlock::try_from(&key[..16]).unwrap();
    let key1 = AesBlock::try_from(&key[16..]).unwrap();

    let kn0 = key0 ^ AesBlock::try_from(&iv[..16]).unwrap();
    let kn1 = key1 ^ AesBlock::try_from(&iv[16..]).unwrap();

    let mut state = [kn0, kn1, CONST_1, CONST_0, key0 ^ CONST_0, key1 ^ CONST_1];

    for _ in 0..4 {
        state_update(&mut state, key0);
        state_update(&mut state, key1);
        state_update(&mut state, kn0);
        state_update(&mut state, kn1);
    }

    state
}

fn ingest_one_block(state: &mut State, aad: &[u8; 16]) {
    state_update(state, aad.into());
}

fn encrypt_one_block(state: &mut State, plaintext: &[u8; 16], ciphertext: &mut [u8; 16]) {
    let p = AesBlock::from(plaintext);
    (p ^ state[1] ^ state[4] ^ state[5] ^ (state[2] & state[3])).store_to(ciphertext);
    state_update(state, p);
}

fn decrypt_one_block(state: &mut State, ciphertext: &[u8; 16], plaintext: &mut [u8; 16]) {
    let p = AesBlock::from(ciphertext) ^ state[1] ^ state[4] ^ state[5] ^ (state[2] & state[3]);
    p.store_to(plaintext);
    state_update(state, p);
}

fn decrypt_last_block(state: &mut State, ciphertext: &[u8], position: usize) -> [u8; 16] {
    let mut temp = [0; 16];
    temp[..position].copy_from_slice(ciphertext);

    let p = AesBlock::from(temp) ^ state[1] ^ state[4] ^ state[5] ^ (state[2] & state[3]);
    p.store_to(&mut temp);

    temp[position..].fill(0);

    state_update(state, temp.into());

    temp
}

fn finalize_state(mut state: State, aad_len: u64, msg_len: u64) -> [u8; 16] {
    let tmp =
        state[3] ^ AesBlock::from(((aad_len.to_be() as u128) << 64) | (msg_len.to_be() as u128));

    for _ in 0..7 {
        state_update(&mut state, tmp);
    }

    (state[0] ^ state[1] ^ state[2] ^ state[3] ^ state[4] ^ state[5]).into()
}

aegis_impl!(Aegis256Enc, Aegis256Dec, 16);
