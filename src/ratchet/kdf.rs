/**
 * ratchet/kdf.rs
 */

use blake3;
use x25519_dalek as x25519;

/// Input: root_key, diffie_hellman_shared_secret
/// Output: (root_key, chain_key)
pub fn kdf_root_key(key: &[u8; 32], shared_secret: x25519::SharedSecret) -> ([u8; 32], [u8; 32]) {
    let mut kdf = blake3::Hasher::new_derive_key("DOUBLE_RATCHET_KDF_ROOT_KEY");
    kdf.update(key);
    kdf.update(shared_secret.as_bytes());
    let mut xof = kdf.finalize_xof();

    let mut root_key = [0u8; 32];
    xof.fill(&mut root_key);

    let mut chain_key = [0u8; 32];
    xof.fill(&mut chain_key);

    (root_key, chain_key)
}

/// Input: chain_key
/// Output: (chain_key, message_key)
pub fn kdf_chain_key(key: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut kdf = blake3::Hasher::new_derive_key("DOUBLE_RATCHET_KDF_CHAIN_KEY");
    kdf.update(key);
    let mut xof = kdf.finalize_xof();

    let mut chain_key = [0u8; 32];
    xof.fill(&mut chain_key);

    let mut message_key = [0u8; 32];
    xof.fill(&mut message_key);

    (chain_key, message_key)
}
