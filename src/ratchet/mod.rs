// ./ratchet/mod.rs
mod types;
mod kdf;
mod encryption;

pub use types::{RatchetState, Message, MessageHeader};
pub use encryption::{send_message, send_bytes, receive_message};
pub use kdf::{kdf_root_key, kdf_chain_key};

/// Initialize Alice's ratchet state with shared key from PQXDH
pub fn init_alice(shared_key: [u8; 32], bob_x25519_public_key: x25519_dalek::PublicKey) -> RatchetState {
    let mut rng = rand::thread_rng();
    let sending_x25519_secret_key = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
    let sending_x25519_public_key = x25519_dalek::PublicKey::from(&sending_x25519_secret_key);

    let receiving_x25519_public_key = Some(bob_x25519_public_key);

    // state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    let (root_key, chain_key_sending) = kdf_root_key(
        &shared_key,
        sending_x25519_secret_key.diffie_hellman(&bob_x25519_public_key),
    );

    RatchetState {
        sending_x25519_secret_key,
        sending_x25519_public_key,
        receiving_x25519_public_key,
        root_key,
        chain_key_sending,
        chain_key_receiving: [0u8; 32],
        sending_counter: 0,
        receiving_counter: 0,
    }
}

/// Initialize Bob's ratchet state with shared key from PQXDH
pub fn init_bob(shared_key: [u8; 32], bob_prekey_private: x25519_dalek::StaticSecret) -> RatchetState {
    let bob_prekey_public = x25519_dalek::PublicKey::from(&bob_prekey_private);

    RatchetState {
        sending_x25519_secret_key: bob_prekey_private,
        sending_x25519_public_key: bob_prekey_public,
        receiving_x25519_public_key: None,
        root_key: shared_key,
        chain_key_sending: [0u8; 32],
        chain_key_receiving: [0u8; 32],
        sending_counter: 0,
        receiving_counter: 0,
    }
}
