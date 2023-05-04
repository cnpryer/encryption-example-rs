// This is an example program used to demonstrate encryption and decryption in Rust.

use std::num::NonZeroU32;

use human_panic::setup_panic;
use ring::{
    aead::*,
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};

fn main() {
    setup_panic!();

    let passphrase = "my secret passphrase";
    let mut data = b"hello, this is my secret message".to_vec();
    let original_data = data.clone();

    let mut nonce_data = [0; 12];
    SystemRandom::new().fill(&mut nonce_data).unwrap();
    let key = derive_key_from_passphrase(passphrase, &nonce_data);

    let key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
    let key = LessSafeKey::new(key);

    let nonce = Nonce::assume_unique_for_key(nonce_data);
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data)
        .unwrap();

    assert_ne!(original_data, data);

    let nonce = Nonce::assume_unique_for_key(nonce_data);
    let data = key.open_in_place(nonce, Aad::empty(), &mut data).unwrap();

    assert_eq!(original_data, data);
}

fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let iterations = 100_000;

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).unwrap(),
        salt,
        passphrase.as_bytes(),
        &mut key,
    );

    key
}
