use anyhow::{anyhow, Result};
use blake3::Hasher;
use ed25519_dalek::Signature;
use pkarr::{Keypair, PublicKey};
use pubky_common::crypto::{decrypt, encrypt};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::crypto::generate_shared_secret;

/// A private message with encrypted sender and content
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PrivateMessage {
    pub timestamp: u64,
    pub encrypted_sender: Vec<u8>,
    pub encrypted_content: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

impl PrivateMessage {
    /// Create a new encrypted message
    pub fn new(sender_keypair: &Keypair, recipient_pk: &PublicKey, content: &str) -> Result<Self> {
        let content_bytes = content.as_bytes();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create message digest for signing
        let mut hasher = Hasher::new();
        hasher.update(content_bytes);
        hasher.update(sender_keypair.public_key().as_bytes());
        hasher.update(&timestamp.to_be_bytes());
        let message_digest = hasher.finalize();

        // Sign the message
        let signature = sender_keypair.sign(message_digest.as_bytes());
        let signature_bytes = signature.to_bytes().to_vec();

        // Generate encryption key from shared secret
        let shared_secret = generate_shared_secret(sender_keypair, recipient_pk)?;
        let shared_secret_bytes = hex::decode(&shared_secret)?;

        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&shared_secret_bytes);

        // Encrypt content and sender
        let encrypted_content = encrypt(content_bytes, &encryption_key);
        let sender_string = sender_keypair.public_key().to_string();
        let encrypted_sender = encrypt(sender_string.as_bytes(), &encryption_key);

        Ok(Self {
            timestamp,
            encrypted_sender,
            encrypted_content,
            signature_bytes,
        })
    }

    /// Decrypt the message content
    pub fn decrypt_content(&self, receiver_keypair: &Keypair, other_participant: &PublicKey) -> Result<String> {
        let shared_secret = generate_shared_secret(receiver_keypair, other_participant)?;
        let shared_secret_bytes = hex::decode(&shared_secret)?;

        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&shared_secret_bytes);

        let decrypted = decrypt(&self.encrypted_content, &encryption_key)?;
        Ok(String::from_utf8(decrypted)?)
    }

    /// Decrypt the sender public key
    pub fn decrypt_sender(&self, receiver_keypair: &Keypair, other_participant: &PublicKey) -> Result<String> {
        let shared_secret = generate_shared_secret(receiver_keypair, other_participant)?;
        let shared_secret_bytes = hex::decode(&shared_secret)?;

        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&shared_secret_bytes);

        let decrypted = decrypt(&self.encrypted_sender, &encryption_key)?;
        Ok(String::from_utf8(decrypted)?)
    }

    /// Verify the message signature
    pub fn verify_signature(&self, decrypted_content: &str, decrypted_sender: &str) -> Result<bool> {
        let sender_pk = PublicKey::try_from(decrypted_sender)?;

        let mut hasher = Hasher::new();
        hasher.update(decrypted_content.as_bytes());
        hasher.update(sender_pk.as_bytes());
        hasher.update(&self.timestamp.to_be_bytes());
        let message_digest = hasher.finalize();

        if self.signature_bytes.len() != 64 {
            return Err(anyhow!("Invalid signature length"));
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature_bytes);
        let signature = Signature::from_bytes(&sig_bytes);

        match sender_pk.verify(message_digest.as_bytes(), &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Generate a unique message ID
    pub fn generate_id() -> String {
        Uuid::new_v4().to_string()
    }
}

/// A decrypted message for application use
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedMessage {
    pub sender: String,
    pub content: String,
    pub timestamp: u64,
    pub verified: bool,
}