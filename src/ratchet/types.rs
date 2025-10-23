/**
 * ratchet/types.rs
 */

use x25519_dalek as x25519;

pub struct RatchetState {
    pub(crate) sending_x25519_secret_key: x25519::StaticSecret,
    pub(crate) sending_x25519_public_key: x25519::PublicKey,
    pub(crate) receiving_x25519_public_key: Option<x25519::PublicKey>,

    pub(crate) root_key: [u8; 32],
    pub(crate) chain_key_sending: [u8; 32],
    pub(crate) chain_key_receiving: [u8; 32],

    pub(crate) sending_counter: u64,
    pub(crate) receiving_counter: u64,
}

pub struct Message {
    pub header: MessageHeader,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct MessageHeader {
    pub x25519_public_key: x25519::PublicKey,
    pub counter: u64,
    pub nonce: [u8; 12],
}
