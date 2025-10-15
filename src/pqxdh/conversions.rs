use ed25519_dalek as ed25519;
use x25519_dalek as x25519;

/// Convert an Ed25519 secret key (the 32-byte seed) into an X25519 secret key
pub fn ed25519_sk_to_x25519(ed25519_secret_key: &ed25519::SigningKey) -> x25519::StaticSecret {
    x25519::StaticSecret::from(ed25519_secret_key.to_scalar_bytes())
}

/// Convert an Ed25519 public key to an X25519 public key
pub fn ed25519_pk_to_x25519(ed25519_public_key: &ed25519::VerifyingKey) -> x25519::PublicKey {
    x25519::PublicKey::from(ed25519_public_key.to_montgomery().to_bytes())
}
