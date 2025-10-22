/**
 * pineapple/src/pqxdh/handshake.rs
 */

use super::types::{User, PQXDHInitOutput, PQXDHInitMessage};
use super::conversions::{ed25519_sk_to_x25519, ed25519_pk_to_x25519};
use anyhow::{Context, Error};
use ed25519_dalek::Verifier;
use ml_kem::{
    EncodedSizeUser,
    kem::{Encapsulate, Decapsulate},
};
use sha3::{Shake256, digest::{ExtendableOutput, Update}};
use x25519_dalek as x25519;

/**
 * TODO-RENAME : Function and parameter names are mid
 */
pub fn init_pqxdh(alice: &User, bob: &User) -> Result<PQXDHInitOutput, Error> {
    /**
     * TODO : This is deprecated, so I have to replace this
     * It seems to be just a rename though...
     * Woah, the source is available at :
     * https://docs.rs/rand/latest/src/rand/lib.rs.html#123-125
     * That'll come in handy if I have to make that
     * random number upgrade.
     * Also I need to refer to the OSDev wiki for that
     * https://wiki.osdev.org/Random_Number_Generator
     *
     * And then there is this for the benchmarking
     * https://simul.iro.umontreal.ca/testu01/tu01.html
     */
    let mut rng = rand::thread_rng();

    // Verify that the prekeys actually come from the intended recipient
    /**
     * Here the return types needs to be Ok(()),
     * else an error is returned.
     * The library does the heavy lifting here.
     */
    bob.identity_public_key
        .verify_strict(bob.x25519_prekey.public_key.as_bytes(), &bob.x25519_prekey.signature)
        .with_context(|| "failed to verify X25519 prekey")?;
    bob.identity_public_key
        .verify_strict(&bob.mlkem1024_prekey.encap_key.as_bytes(), &bob.mlkem1024_prekey.signature)
        .with_context(|| "failed to verify ML-KEM-1024 prekey")?;

    let ephemeral_x25519_private_key = x25519::StaticSecret::random_from_rng(&mut rng);

    // Try to use one-time ML-KEM prekey first (preferred), else use signed prekey (last-resort)
    let (mlkem_ciphertext, mlkem_shared_secret, used_one_time_mlkem) = 
        if !bob.one_time_mlkem_prekeys.is_empty() {
            let (_, pqotp) = &bob.one_time_mlkem_prekeys[0];
            // Verify one-time prekey signature
            bob.identity_public_key
                .verify_strict(&pqotp.encap_key.as_bytes(), &pqotp.signature)
                .with_context(|| "failed to verify one-time ML-KEM prekey")?;
            
            let (ct, ss) = pqotp.encap_key
                .encapsulate(&mut rng)
                .map_err(|_| Error::msg("failed to encapsulate with one-time ML-KEM-1024"))?;
            (ct, ss, true)
        } else {
            let (ct, ss) = bob.mlkem1024_prekey.encap_key
                .encapsulate(&mut rng)
                .map_err(|_| Error::msg("failed to encapsulate with ML-KEM-1024"))?;
            (ct, ss, false)
        };

    // Convert the Ed25519 keys to X25519 keys for the Diffie-Hellman key exchanges
    let alice_identity_secret_key_x25519 = ed25519_sk_to_x25519(&alice.identity_private_key);
    let bob_identity_public_key_x25519 = ed25519_pk_to_x25519(&bob.identity_public_key);

    // DH1 = DH(IKA, SPKB)
    let dh_1 = alice_identity_secret_key_x25519.diffie_hellman(&bob.x25519_prekey.public_key);
    // DH2 = DH(EKA, IKB)
    let dh_2 = ephemeral_x25519_private_key.diffie_hellman(&bob_identity_public_key_x25519);
    // DH3 = DH(EKA, SPKB)
    let dh_3 = ephemeral_x25519_private_key.diffie_hellman(&bob.x25519_prekey.public_key);

    // DH4 = DH(EKA, OPKB) - only if one-time prekey is available
    let (dh_4_opt, used_one_time_x25519) = if !bob.one_time_x25519_prekeys.is_empty() {
        let (_, opk) = &bob.one_time_x25519_prekeys[0];
        // Verify one-time prekey signature
        bob.identity_public_key
            .verify_strict(opk.public_key.as_bytes(), &opk.signature)
            .with_context(|| "failed to verify one-time X25519 prekey")?;
        
        let dh4 = ephemeral_x25519_private_key.diffie_hellman(&opk.public_key);
        (Some(dh4), true)
    } else {
        (None, false)
    };

    // SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)
    let secret_key = kdf(
        dh_1.as_bytes(),
        dh_2.as_bytes(),
        dh_3.as_bytes(),
        dh_4_opt.as_ref().map(|dh| dh.as_bytes() as &[u8]),
        &mlkem_shared_secret,
    );

    // Construct associated data: EncodeEC(IK_A) || EncodeEC(IK_B)
    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(alice.identity_public_key.as_bytes());
    associated_data.extend_from_slice(bob.identity_public_key.as_bytes());

    let init_message = PQXDHInitMessage {
        peer_identity_public_key: alice.identity_public_key,
        ephemeral_x25519_public_key: x25519::PublicKey::from(&ephemeral_x25519_private_key),
        mlkem_ciphertext: mlkem_ciphertext.to_vec(),
        used_one_time_x25519,
        used_one_time_mlkem,
    };

    Ok(PQXDHInitOutput {
        secret_key,
        message: init_message,
        bob_ratchet_key: bob.x25519_prekey.public_key,
        associated_data,
    })
}

pub fn complete_pqxdh(bob: &mut User, message: &PQXDHInitMessage) -> Result<([u8; 32], Vec<u8>), Error> {
    // Decapsulate using the appropriate ML-KEM key
    let mlkem_shared_secret = if message.used_one_time_mlkem {
        if bob.one_time_mlkem_prekeys.is_empty() {
            return Err(Error::msg("One-time ML-KEM prekey was used but not available"));
        }
        let (decap_key, _) = bob.one_time_mlkem_prekeys.remove(0);
        decap_key
            .decapsulate(message.mlkem_ciphertext.as_slice().try_into().unwrap())
            .map_err(|_| Error::msg("failed to decapsulate with one-time ML-KEM-1024"))?
    } else {
        bob.mlkem1024_prekey_decap_key
            .decapsulate(message.mlkem_ciphertext.as_slice().try_into().unwrap())
            .map_err(|_| Error::msg("failed to decapsulate with ML-KEM-1024"))?
    };

    // Convert the Ed25519 keys to X25519 keys for the Diffie-Hellman key exchanges
    let alice_identity_public_key_x25519 = ed25519_pk_to_x25519(&message.peer_identity_public_key);
    let bob_identity_secret_key_x25519 = ed25519_sk_to_x25519(&bob.identity_private_key);

    // DH1 = DH(IKA, SPKB)
    let dh_1 = bob.x25519_prekey_private_key.diffie_hellman(&alice_identity_public_key_x25519);
    // DH2 = DH(EKA, IKB)
    let dh_2 = bob_identity_secret_key_x25519.diffie_hellman(&message.ephemeral_x25519_public_key);
    // DH3 = DH(EKA, SPKB)
    let dh_3 = bob
        .x25519_prekey_private_key
        .diffie_hellman(&message.ephemeral_x25519_public_key);

    // DH4 if one-time prekey was used
    let dh_4_opt = if message.used_one_time_x25519 {
        if bob.one_time_x25519_prekeys.is_empty() {
            return Err(Error::msg("One-time X25519 prekey was used but not available"));
        }
        let (opk_secret, _) = bob.one_time_x25519_prekeys.remove(0);
        let dh4 = opk_secret.diffie_hellman(&message.ephemeral_x25519_public_key);
        Some(dh4)
    } else {
        None
    };

    // SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)
    let secret_key = kdf(
        dh_1.as_bytes(),
        dh_2.as_bytes(),
        dh_3.as_bytes(),
        dh_4_opt.as_ref().map(|dh| dh.as_bytes() as &[u8]),
        &mlkem_shared_secret,
    );

    // Construct associated data
    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(message.peer_identity_public_key.as_bytes());
    associated_data.extend_from_slice(bob.identity_public_key.as_bytes());

    // One-time prekey private keys are deleted above when removed from the vectors (forward secrecy)

    Ok((secret_key, associated_data))
}

fn kdf(
    dh1: &[u8],
    dh2: &[u8],
    dh3: &[u8],
    dh4: Option<&[u8]>,
    mlkem_shared_secret: &[u8],
) -> [u8; 32] {
    static KDF_INFO: &[u8] = b"PQXDH_CURVE25519_SHAKE256_ML-KEM-1024";

    let mut secret_key = [0u8; 32];
    let mut kdf = Shake256::default();
    kdf.update(&[0xffu8; 32]);
    kdf.update(dh1);
    kdf.update(dh2);
    kdf.update(dh3);
    if let Some(dh4_bytes) = dh4 {
        kdf.update(dh4_bytes);
    }
    kdf.update(mlkem_shared_secret);
    kdf.update(KDF_INFO);
    kdf.finalize_xof_into(&mut secret_key);
    secret_key
}
