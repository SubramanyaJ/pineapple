/**
 * network.rs
 */

use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use ml_kem::EncodedSizeUser;

use crate::pqxdh::{PQXDHInitMessage, User, SignedX25519Prekey, SignedMlKem1024Prekey};
use crate::ratchet::{Message, MessageHeader};

/// Serialize a PQXDH initial message for network transmission
pub fn serialize_pqxdh_init_message(msg: &PQXDHInitMessage) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Identity public key (32 bytes)
    buffer.extend_from_slice(msg.peer_identity_public_key.as_bytes());

    // Ephemeral X25519 public key (32 bytes)
    buffer.extend_from_slice(msg.ephemeral_x25519_public_key.as_bytes());

    // ML-KEM ciphertext length (4 bytes) + ciphertext
    buffer.extend_from_slice(&(msg.mlkem_ciphertext.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&msg.mlkem_ciphertext);

    // One-time prekey usage flags (2 bytes)
    buffer.push(if msg.used_one_time_x25519 { 1 } else { 0 });
    buffer.push(if msg.used_one_time_mlkem { 1 } else { 0 });

    buffer
}

/// Deserialize a PQXDH initial message from network data
pub fn deserialize_pqxdh_init_message(data: &[u8]) -> Result<PQXDHInitMessage> {
    if data.len() < 68 {
        anyhow::bail!("PQXDH message too short");
    }

    let mut offset = 0;

    // Identity public key
    let peer_identity_bytes: [u8; 32] = data[offset..offset + 32]
        .try_into()
        .context("Invalid identity key")?;
    let peer_identity_public_key = ed25519_dalek::VerifyingKey::from_bytes(&peer_identity_bytes)
        .context("Failed to parse identity key")?;
    offset += 32;

    // Ephemeral X25519 public key
    let ephemeral_bytes: [u8; 32] = data[offset..offset + 32]
        .try_into()
        .context("Invalid ephemeral key")?;
    let ephemeral_x25519_public_key = x25519_dalek::PublicKey::from(ephemeral_bytes);
    offset += 32;

    // ML-KEM ciphertext
    let ct_len = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .context("Invalid ciphertext length")?,
    ) as usize;
    offset += 4;

    let mlkem_ciphertext = data[offset..offset + ct_len].to_vec();
    offset += ct_len;

    // One-time prekey usage flags
    let used_one_time_x25519 = data[offset] == 1;
    let used_one_time_mlkem = data[offset + 1] == 1;

    Ok(PQXDHInitMessage {
        peer_identity_public_key,
        ephemeral_x25519_public_key,
        mlkem_ciphertext,
        used_one_time_x25519,
        used_one_time_mlkem,
    })
}

/// Serialize a Bob's public keys for prekey bundle
pub fn serialize_prekey_bundle(bob: &User) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Identity key (32 bytes)
    buffer.extend_from_slice(bob.identity_public_key.as_bytes());

    // Signed X25519 prekey (32 bytes + 64 bytes signature)
    buffer.extend_from_slice(bob.x25519_prekey.public_key.as_bytes());
    buffer.extend_from_slice(&bob.x25519_prekey.signature.to_bytes());

    // ML-KEM prekey (variable length)
    let mlkem_bytes = bob.mlkem1024_prekey.encap_key.as_bytes();
    buffer.extend_from_slice(&(mlkem_bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&mlkem_bytes);
    buffer.extend_from_slice(&bob.mlkem1024_prekey.signature.to_bytes());

    // One-time prekey availability flags (2 bytes)
    buffer.push(if !bob.one_time_x25519_prekeys.is_empty() { 1 } else { 0 });
    buffer.push(if !bob.one_time_mlkem_prekeys.is_empty() { 1 } else { 0 });

    // If one-time prekeys available, include one of each
    if !bob.one_time_x25519_prekeys.is_empty() {
        let (_, otp) = &bob.one_time_x25519_prekeys[0];
        buffer.extend_from_slice(otp.public_key.as_bytes());
        buffer.extend_from_slice(&otp.signature.to_bytes());
    }

    if !bob.one_time_mlkem_prekeys.is_empty() {
        let (_, pqotp) = &bob.one_time_mlkem_prekeys[0];
        let pqotp_bytes = pqotp.encap_key.as_bytes();
        buffer.extend_from_slice(&(pqotp_bytes.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&pqotp_bytes);
        buffer.extend_from_slice(&pqotp.signature.to_bytes());
    }

    buffer
}

/// Deserialize Bob's prekey bundle
pub fn deserialize_prekey_bundle(data: &[u8]) -> Result<User> {
    let mut offset = 0;

    // Identity key
    let identity_bytes: [u8; 32] = data[offset..offset + 32]
        .try_into()
        .context("Invalid identity key")?;
    let identity_public_key = ed25519_dalek::VerifyingKey::from_bytes(&identity_bytes)
        .context("Failed to parse identity key")?;
    offset += 32;

    // X25519 prekey
    let x25519_bytes: [u8; 32] = data[offset..offset + 32]
        .try_into()
        .context("Invalid X25519 prekey")?;
    let x25519_public_key = x25519_dalek::PublicKey::from(x25519_bytes);
    offset += 32;

    let x25519_sig_bytes: [u8; 64] = data[offset..offset + 64]
        .try_into()
        .context("Invalid X25519 signature")?;
    let x25519_signature = ed25519_dalek::Signature::from_bytes(&x25519_sig_bytes);
    offset += 64;

    let x25519_prekey = SignedX25519Prekey {
        public_key: x25519_public_key,
        signature: x25519_signature,
    };

    // ML-KEM prekey
    let mlkem_len = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .context("Invalid ML-KEM length")?,
    ) as usize;
    offset += 4;

    if mlkem_len != 1568 {
        anyhow::bail!("Invalid ML-KEM-1024 encapsulation key length: {}", mlkem_len);
    }

    let mlkem_bytes: &[u8; 1568] = data[offset..offset + mlkem_len]
        .try_into()
        .context("Invalid ML-KEM bytes")?;
    let mlkem_encap_key =
        ml_kem::kem::EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(mlkem_bytes.into());
    offset += mlkem_len;

    let mlkem_sig_bytes: [u8; 64] = data[offset..offset + 64]
        .try_into()
        .context("Invalid ML-KEM signature")?;
    let mlkem_signature = ed25519_dalek::Signature::from_bytes(&mlkem_sig_bytes);
    offset += 64;

    let mlkem_prekey = SignedMlKem1024Prekey {
        encap_key: mlkem_encap_key,
        signature: mlkem_signature,
    };

    // One-time prekey flags
    let has_x25519_otp = data[offset] == 1;
    let has_mlkem_otp = data[offset + 1] == 1;
    offset += 2;

    let mut one_time_x25519_prekey = None;
    if has_x25519_otp {
        let otp_bytes: [u8; 32] = data[offset..offset + 32]
            .try_into()
            .context("Invalid one-time X25519 key")?;
        let otp_public = x25519_dalek::PublicKey::from(otp_bytes);
        offset += 32;

        let otp_sig_bytes: [u8; 64] = data[offset..offset + 64]
            .try_into()
            .context("Invalid one-time X25519 signature")?;
        let otp_signature = ed25519_dalek::Signature::from_bytes(&otp_sig_bytes);
        offset += 64;

        one_time_x25519_prekey = Some(SignedX25519Prekey {
            public_key: otp_public,
            signature: otp_signature,
        });
    }

    let mut one_time_mlkem_prekey = None;
    if has_mlkem_otp {
        let pqotp_len = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .context("Invalid one-time ML-KEM length")?,
        ) as usize;
        offset += 4;

        if pqotp_len != 1568 {
            anyhow::bail!("Invalid one-time ML-KEM-1024 encapsulation key length: {}", pqotp_len);
        }

        let pqotp_bytes: &[u8; 1568] = data[offset..offset + pqotp_len]
            .try_into()
            .context("Invalid one-time ML-KEM bytes")?;
        let pqotp_encap_key =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(pqotp_bytes.into());
        offset += pqotp_len;

        let pqotp_sig_bytes: [u8; 64] = data[offset..offset + 64]
            .try_into()
            .context("Invalid one-time ML-KEM signature")?;
        let pqotp_signature = ed25519_dalek::Signature::from_bytes(&pqotp_sig_bytes);

        one_time_mlkem_prekey = Some(SignedMlKem1024Prekey {
            encap_key: pqotp_encap_key,
            signature: pqotp_signature,
        });
    }

    Ok(User::from_public_keys(
        identity_public_key,
        x25519_prekey,
        mlkem_prekey,
        one_time_x25519_prekey,
        one_time_mlkem_prekey,
    ))
}

/// Serialize a ratchet message for network transmission
pub fn serialize_ratchet_message(msg: &Message) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Header: X25519 public key (32 bytes)
    buffer.extend_from_slice(msg.header.x25519_public_key.as_bytes());

    // Counter (8 bytes)
    buffer.extend_from_slice(&msg.header.counter.to_be_bytes());

    // Nonce (12 bytes)
    buffer.extend_from_slice(&msg.header.nonce);

    // Ciphertext length (4 bytes) + ciphertext
    buffer.extend_from_slice(&(msg.ciphertext.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&msg.ciphertext);

    buffer
}

/// Deserialize a ratchet message from network data
pub fn deserialize_ratchet_message(data: &[u8]) -> Result<Message> {
    if data.len() < 56 {
        anyhow::bail!("Ratchet message too short");
    }

    let mut offset = 0;

    // X25519 public key
    let pk_bytes: [u8; 32] = data[offset..offset + 32]
        .try_into()
        .context("Invalid public key")?;
    let x25519_public_key = x25519_dalek::PublicKey::from(pk_bytes);
    offset += 32;

    // Counter
    let counter = u64::from_be_bytes(
        data[offset..offset + 8]
            .try_into()
            .context("Invalid counter")?,
    );
    offset += 8;

    // Nonce
    let nonce: [u8; 12] = data[offset..offset + 12]
        .try_into()
        .context("Invalid nonce")?;
    offset += 12;

    // Ciphertext
    let ct_len = u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .context("Invalid ciphertext length")?,
    ) as usize;
    offset += 4;

    let ciphertext = data[offset..offset + ct_len].to_vec();

    Ok(Message {
        header: MessageHeader {
            x25519_public_key,
            counter,
            nonce,
        },
        ciphertext,
    })
}

/// Send a length-prefixed message over TCP
pub fn send_message(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .context("Failed to write message length")?;
    stream
        .write_all(data)
        .context("Failed to write message data")?;
    stream.flush().context("Failed to flush stream")?;
    Ok(())
}

/// Receive a length-prefixed message from TCP
pub fn receive_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .context("Failed to read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 10_000_000 {
        anyhow::bail!("Message too large: {} bytes", len);
    }

    let mut buffer = vec![0u8; len];
    stream
        .read_exact(&mut buffer)
        .context("Failed to read message data")?;
    Ok(buffer)
}
