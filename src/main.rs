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

    // Have some data and a passphrase. I'd like to use the passphrase to encrypt my data.
    let passphrase = "my secret passphrase";
    let mut data = b"hello, this is my secret message".to_vec();

    // Keep track of what the original unencrypted data was.
    let original_data = data.clone();

    // Create a nonce to use for the algorithms.
    let mut nonce_data = [0; 12];
    SystemRandom::new().fill(&mut nonce_data).unwrap();

    // Generate a key from your passphrase. This key is used to encrypt and decrypt the data.
    let key = derive_key(passphrase, &nonce_data);
    let key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();
    let key = LessSafeKey::new(key);

    // Generate nonces for the operations.
    let encrypt_nonce = Nonce::assume_unique_for_key(nonce_data);
    let decrypt_nonce = Nonce::assume_unique_for_key(nonce_data);

    // Encrypt the data.
    key.seal_in_place_append_tag(encrypt_nonce, Aad::empty(), &mut data)
        .unwrap();

    // Check if the data changed.
    assert_ne!(original_data, data);

    // Decrypt the encrypted data.
    let data = key
        .open_in_place(decrypt_nonce, Aad::empty(), &mut data)
        .unwrap();

    // Check if the decrypted data is the same as the original.
    assert_eq!(original_data, data);
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
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
