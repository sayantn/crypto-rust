use crate::aegis::{aegis_impl, AEGIS_X2_CTX, CONST_0, CONST_1};
use aes_crypto::{AesBlock, AesBlockX2};

pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 32;
pub const MAX_TAG_LEN: usize = 16;

type State = [AesBlockX2; 6];

fn state_update(state: &mut State, m: AesBlockX2) {
    let temp = state[5];

    state[5] = state[4].enc(state[5]);
    state[4] = state[3].enc(state[4]);
    state[3] = state[2].enc(state[3]);
    state[2] = state[1].enc(state[2]);
    state[1] = state[0].enc(state[1]);
    state[0] = temp.enc(state[0] ^ m);
}

fn initialize(key: [u8; KEY_LEN], iv: [u8; IV_LEN]) -> State {
    let const_0 = CONST_0.into();
    let const_1 = CONST_1.into();

    let key0 = AesBlock::try_from(&key[..16]).unwrap().into();
    let key1 = AesBlock::try_from(&key[16..]).unwrap().into();

    let kn0 = key0 ^ AesBlock::try_from(&iv[..16]).unwrap().into();
    let kn1 = key1 ^ AesBlock::try_from(&iv[16..]).unwrap().into();

    let mut state = [kn0, kn1, const_1, const_0, key0 ^ const_0, key1 ^ const_1];

    let ctx = AEGIS_X2_CTX;

    for _ in 0..4 {
        state[3] ^= ctx;
        state[5] ^= ctx;
        state_update(&mut state, key0);
        state[3] ^= ctx;
        state[5] ^= ctx;
        state_update(&mut state, key1);
        state[3] ^= ctx;
        state[5] ^= ctx;
        state_update(&mut state, kn0);
        state[3] ^= ctx;
        state[5] ^= ctx;
        state_update(&mut state, kn1);
    }

    state
}

fn ingest_one_block(state: &mut State, aad: &[u8; 32]) {
    state_update(state, aad.into());
}

fn encrypt_one_block(state: &mut State, plaintext: &[u8; 32], ciphertext: &mut [u8; 32]) {
    let p = AesBlockX2::from(plaintext);
    (p ^ state[1] ^ state[4] ^ state[5] ^ (state[2] & state[3])).store_to(ciphertext);
    state_update(state, p);
}

fn decrypt_one_block(state: &mut State, ciphertext: &[u8; 32], plaintext: &mut [u8; 32]) {
    let p = AesBlockX2::from(ciphertext) ^ state[1] ^ state[4] ^ state[5] ^ (state[2] & state[3]);
    p.store_to(plaintext);
    state_update(state, p);
}

fn decrypt_last_block(state: &mut State, ciphertext: &[u8], position: usize) -> [u8; 32] {
    let mut temp = [0; 32];
    temp[..position].copy_from_slice(ciphertext);

    let p = AesBlockX2::from(temp) ^ state[1] ^ state[4] ^ state[5] ^ (state[2] & state[3]);
    p.store_to(&mut temp);

    temp[position..].fill(0);

    state_update(state, temp.into());

    temp
}

fn finalize_state(mut state: State, aad_len: u64, msg_len: u64) -> [u8; MAX_TAG_LEN] {
    let tmp = state[3]
        ^ AesBlock::from(((aad_len.to_be() as u128) << 64) | (msg_len.to_be() as u128)).into();

    for _ in 0..7 {
        state_update(&mut state, tmp);
    }

    let (tag0, tag1) = (state[0] ^ state[1] ^ state[2] ^ state[3] ^ state[4] ^ state[5]).into();
    (tag0 ^ tag1).into()
}

aegis_impl!(Aegis256X2Enc, Aegis256X2Dec, 32);
