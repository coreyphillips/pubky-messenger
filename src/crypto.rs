use anyhow::{anyhow, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hex;
use pkarr::{Keypair, PublicKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Convert Ed25519 public key to X25519 public key
pub fn ed25519_public_to_x25519(ed_pub: &[u8; 32]) -> Option<X25519PublicKey> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards_point = compressed.decompress()?;
    Some(X25519PublicKey::from(
        edwards_point.to_montgomery().to_bytes(),
    ))
}

/// Convert Ed25519 secret key to X25519 secret key
pub fn ed25519_secret_to_x25519(ed_secret: &[u8; 32]) -> StaticSecret {
    let mut hasher = Sha512::new();
    hasher.update(ed_secret);
    let hash = hasher.finalize();

    let mut x25519_secret_bytes = [0u8; 32];
    x25519_secret_bytes.copy_from_slice(&hash[0..32]);

    // Apply clamping as per RFC 7748
    x25519_secret_bytes[0] &= 248;
    x25519_secret_bytes[31] &= 127;
    x25519_secret_bytes[31] |= 64;

    StaticSecret::from(x25519_secret_bytes)
}

/// Shared secret of a two-party conversation: the encryption key for every message in it,
/// and the source of its storage path.
///
/// Derive it once per operation and let it drop with the operation, rather than caching it.
pub struct ConversationKey([u8; 32]);

impl ConversationKey {
    /// Derive the key both participants compute for the conversation between them
    pub fn derive(keypair: &Keypair, other_pubky: &PublicKey) -> Result<Self> {
        let ed25519_secret = keypair.secret_key();
        let x25519_secret = ed25519_secret_to_x25519(&ed25519_secret);

        let other_pubky_bytes = other_pubky.as_bytes();
        if other_pubky_bytes.len() != 32 {
            return Err(anyhow!("Invalid public key length"));
        }

        let mut other_ed_bytes = [0u8; 32];
        other_ed_bytes.copy_from_slice(other_pubky_bytes);

        let other_x25519 = ed25519_public_to_x25519(&other_ed_bytes)
            .ok_or_else(|| anyhow!("Failed to convert pubky to X25519"))?;

        let shared = x25519_secret.diffie_hellman(&other_x25519);
        Ok(Self(*shared.as_bytes()))
    }

    /// Key for encrypting and decrypting message content and sender
    pub fn encryption_key(&self) -> &[u8; 32] {
        &self.0
    }

    /// Deterministic conversation directory, relative to either participant's root
    pub fn path(&self) -> String {
        // Existing conversations live under the hash of the hex-encoded secret
        let path_id = blake3::hash(hex::encode(self.0).as_bytes()).to_hex();
        format!("/pub/private_messages/{}/", path_id)
    }
}

/// Generate deterministic conversation path for two parties
pub fn generate_conversation_path(keypair: &Keypair, other_pubky: &PublicKey) -> Result<String> {
    Ok(ConversationKey::derive(keypair, other_pubky)?.path())
}
