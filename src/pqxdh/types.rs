use ed25519_dalek::{self as ed25519, Signer};
use ml_kem::{
    kem::{DecapsulationKey, EncapsulationKey},
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use x25519_dalek as x25519;

pub struct User {
    pub(crate) identity_private_key: ed25519::SigningKey,
    pub identity_public_key: ed25519::VerifyingKey,

    pub(crate) x25519_prekey_private_key: x25519::StaticSecret,
    pub x25519_prekey: SignedX25519Prekey,

    pub(crate) mlkem1024_prekey_decap_key: DecapsulationKey<MlKem1024Params>,
    pub mlkem1024_prekey: SignedMlKem1024Prekey,

    // One-time prekeys for enhanced forward secrecy
    pub(crate) one_time_x25519_prekeys: Vec<(x25519::StaticSecret, SignedX25519Prekey)>,
    pub(crate) one_time_mlkem_prekeys: Vec<(DecapsulationKey<MlKem1024Params>, SignedMlKem1024Prekey)>,
}

#[derive(Clone)]
pub struct SignedX25519Prekey {
    pub public_key: x25519::PublicKey,
    pub signature: ed25519::Signature,
}

#[derive(Clone)]
pub struct SignedMlKem1024Prekey {
    pub encap_key: EncapsulationKey<MlKem1024Params>,
    pub signature: ed25519::Signature,
}

pub struct PQXDHInitOutput {
    pub secret_key: [u8; 32],
    pub message: PQXDHInitMessage,
    pub bob_ratchet_key: x25519::PublicKey,
    pub associated_data: Vec<u8>,
}

pub struct PQXDHInitMessage {
    pub peer_identity_public_key: ed25519::VerifyingKey,
    pub ephemeral_x25519_public_key: x25519::PublicKey,
    pub mlkem_ciphertext: Vec<u8>,
    pub used_one_time_x25519: bool,  // Whether OPK was used
    pub used_one_time_mlkem: bool,   // Whether PQOPK was used
}

impl User {
    pub fn new() -> User {
        let mut rng = rand::thread_rng();

        let identity_private_key = ed25519::SigningKey::generate(&mut rng);
        let identity_public_key = identity_private_key.verifying_key();

        // Signed prekey (long-term)
        let x25519_private_key = x25519::StaticSecret::random_from_rng(&mut rng);
        let x25519_public_prekey = x25519::PublicKey::from(&x25519_private_key);
        let x25519_public_prekey_signature = identity_private_key.sign(x25519_public_prekey.as_bytes());
        let x25519_prekey = SignedX25519Prekey {
            public_key: x25519_public_prekey,
            signature: x25519_public_prekey_signature,
        };

        // ML-KEM signed prekey (last-resort)
        let (mlkem1024_decap_key, mlkem1024_encap_key) = MlKem1024::generate(&mut rng);
        let mlkem1024_encap_key_signature = identity_private_key.sign(&mlkem1024_encap_key.as_bytes());
        let mlkem1024_prekey = SignedMlKem1024Prekey {
            encap_key: mlkem1024_encap_key,
            signature: mlkem1024_encap_key_signature,
        };

        // Generate 10 one-time X25519 prekeys
        let mut one_time_x25519_prekeys = Vec::new();
        for _ in 0..10 {
            let secret = x25519::StaticSecret::random_from_rng(&mut rng);
            let public = x25519::PublicKey::from(&secret);
            let signature = identity_private_key.sign(public.as_bytes());
            one_time_x25519_prekeys.push((
                secret,
                SignedX25519Prekey {
                    public_key: public,
                    signature,
                },
            ));
        }

        // Generate 10 one-time ML-KEM prekeys
        let mut one_time_mlkem_prekeys = Vec::new();
        for _ in 0..10 {
            let (decap_key, encap_key) = MlKem1024::generate(&mut rng);
            let signature = identity_private_key.sign(&encap_key.as_bytes());
            one_time_mlkem_prekeys.push((
                decap_key,
                SignedMlKem1024Prekey {
                    encap_key,
                    signature,
                },
            ));
        }

        User {
            identity_private_key,
            identity_public_key,
            x25519_prekey_private_key: x25519_private_key,
            x25519_prekey,
            mlkem1024_prekey_decap_key: mlkem1024_decap_key,
            mlkem1024_prekey,
            one_time_x25519_prekeys,
            one_time_mlkem_prekeys,
        }
    }

    /// Create a User representation from public keys only (for remote peer)
    pub fn from_public_keys(
        identity_public_key: ed25519::VerifyingKey,
        x25519_prekey: SignedX25519Prekey,
        mlkem1024_prekey: SignedMlKem1024Prekey,
        one_time_x25519_prekey: Option<SignedX25519Prekey>,
        one_time_mlkem_prekey: Option<SignedMlKem1024Prekey>,
    ) -> User {
        let mut rng = rand::thread_rng();
        
        // Generate dummy private keys (won't be used for remote peer)
        let dummy_identity_private = ed25519::SigningKey::generate(&mut rng);
        let dummy_x25519_private = x25519::StaticSecret::random_from_rng(&mut rng);
        let (dummy_mlkem_decap, _) = MlKem1024::generate(&mut rng);

        let mut one_time_x25519_prekeys = Vec::new();
        if let Some(otp) = one_time_x25519_prekey {
            let dummy_secret = x25519::StaticSecret::random_from_rng(&mut rng);
            one_time_x25519_prekeys.push((dummy_secret, otp));
        }

        let mut one_time_mlkem_prekeys = Vec::new();
        if let Some(pqotp) = one_time_mlkem_prekey {
            let (dummy_decap, _) = MlKem1024::generate(&mut rng);
            one_time_mlkem_prekeys.push((dummy_decap, pqotp));
        }

        User {
            identity_private_key: dummy_identity_private,
            identity_public_key,
            x25519_prekey_private_key: dummy_x25519_private,
            x25519_prekey,
            mlkem1024_prekey_decap_key: dummy_mlkem_decap,
            mlkem1024_prekey,
            one_time_x25519_prekeys,
            one_time_mlkem_prekeys,
        }
    }

    /// Get count of remaining one-time prekeys
    pub fn one_time_prekey_count(&self) -> (usize, usize) {
        (self.one_time_x25519_prekeys.len(), self.one_time_mlkem_prekeys.len())
    }
}
