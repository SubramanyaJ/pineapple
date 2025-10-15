use crate::pqxdh::{self, User, PQXDHInitMessage};
use crate::ratchet::{self, RatchetState, Message};
use anyhow::Result;

/// A complete secure messaging session
pub struct Session {
    ratchet: RatchetState,
    associated_data: Vec<u8>,
}

impl Session {
    /// Create a new session as the initiator
    pub fn new_initiator(alice: &User, bob: &mut User) -> Result<(Self, PQXDHInitMessage)> {
        // Phase 1: PQXDH key agreement (bob is mutable to consume one-time prekeys)
        let pqxdh_output = pqxdh::init_pqxdh(alice, bob)?;

        // Phase 2: Initialize Double Ratchet
        let ratchet = ratchet::init_alice(
            pqxdh_output.secret_key,
            pqxdh_output.bob_ratchet_key,
        );

        let session = Session {
            ratchet,
            associated_data: pqxdh_output.associated_data,
        };

        Ok((session, pqxdh_output.message))
    }

    /// Create a new session as the responder
    pub fn new_responder(bob: &mut User, init_message: &PQXDHInitMessage) -> Result<Self> {
        // Phase 1: Complete PQXDH (bob is mutable for potential one-time prekey deletion)
        let (secret_key, associated_data) = pqxdh::complete_pqxdh(bob, init_message)?;

        // Phase 2: Initialize Double Ratchet
        let ratchet = ratchet::init_bob(secret_key, bob.x25519_prekey_private_key.clone());

        Ok(Session {
            ratchet,
            associated_data,
        })
    }

    /// Send an encrypted message
    pub fn send(&mut self, plaintext: &str) -> Result<Message> {
        ratchet::send_message(&mut self.ratchet, plaintext, &self.associated_data)
    }

    /// Receive and decrypt a message
    pub fn receive(&mut self, message: Message) -> Result<String> {
        ratchet::receive_message(&mut self.ratchet, message, &self.associated_data)
    }
}
