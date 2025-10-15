use super::types::{RatchetState, Message, MessageHeader};
use super::kdf::{kdf_root_key, kdf_chain_key};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{AeadMut, Payload}};
use anyhow::{Error, Context};
use x25519_dalek as x25519;

pub fn send_message(state: &mut RatchetState, plaintext: &str, additional_data: &[u8]) -> Result<Message, Error> {
    // state.CKs, mk = KDF_CK(state.CKs)
    let (new_chain_key_sending, message_key) = kdf_chain_key(&state.chain_key_sending);
    state.chain_key_sending = new_chain_key_sending;

    // Safe to use random nonce as each message uses a different key
    let nonce: [u8; 12] = rand::random();

    let header = MessageHeader {
        x25519_public_key: state.sending_x25519_public_key,
        counter: state.sending_counter,
        nonce,
    };

    // ENCRYPT(mk, plaintext, AD || header)
    let mut cipher = ChaCha20Poly1305::new(&message_key.try_into().unwrap());
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext.as_bytes(),
                aad: additional_data,
            },
        )
        .map_err(|_| Error::msg("Failed to encrypt message"))?;  // Changed from .context()

    state.sending_counter += 1;

    Ok(Message { header, ciphertext })
}

pub fn receive_message(state: &mut RatchetState, message: Message, additional_data: &[u8]) -> Result<String, Error> {
    // If the sender has sent a new Diffie-Hellman public key, perform the DH ratchet
    if state.receiving_x25519_public_key != Some(message.header.x25519_public_key) {
        // state.DHr = header.dh
        state.receiving_x25519_public_key = Some(message.header.x25519_public_key);

        // state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
        (state.root_key, state.chain_key_receiving) = kdf_root_key(
            &state.root_key,
            state.sending_x25519_secret_key
                .diffie_hellman(&state.receiving_x25519_public_key.unwrap()),
        );

        // Generate a new Diffie-Hellman keypair
        let mut rng = rand::thread_rng();
        state.sending_x25519_secret_key = x25519::StaticSecret::random_from_rng(&mut rng);
        state.sending_x25519_public_key = x25519::PublicKey::from(&state.sending_x25519_secret_key);

        // state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
        (state.root_key, state.chain_key_sending) = kdf_root_key(
            &state.root_key,
            state.sending_x25519_secret_key
                .diffie_hellman(&state.receiving_x25519_public_key.unwrap()),
        );
    }

    // state.CKr, mk = KDF_CK(state.CKr)
    let (chain_key_receiving, message_key) = kdf_chain_key(&state.chain_key_receiving);
    state.chain_key_receiving = chain_key_receiving;

    // DECRYPT(mk, ciphertext, CONCAT(AD, header))
    let mut cipher = ChaCha20Poly1305::new(&message_key.try_into().unwrap());
    let plaintext = cipher
        .decrypt(
            (&message.header.nonce).into(),
            Payload {
                msg: &message.ciphertext,
                aad: additional_data,
            },
        )
        .map_err(|_| Error::msg("Failed to decrypt message"))?;  // Changed from .context()

    let message_plaintext = String::from_utf8(plaintext)
        .context("Decrypted message is not valid UTF-8")?;

    state.receiving_counter += 1;

    Ok(message_plaintext)
}
