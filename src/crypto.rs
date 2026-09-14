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
        // A small-order key yields the all-zero secret for every sender, making the key public
        if !shared.was_contributory() {
            return Err(anyhow!(
                "Public key is a weak key and cannot be used for encryption"
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::PrivateMessage;

    /// Canonical encodings of the eight Ed25519 torsion points
    const SMALL_ORDER_KEYS: [&str; 8] = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ];

    fn small_order_keys() -> Vec<PublicKey> {
        SMALL_ORDER_KEYS
            .iter()
            .map(|encoded| {
                let bytes: [u8; 32] = hex::decode(encoded).unwrap().try_into().unwrap();
                let point = CompressedEdwardsY(bytes).decompress().unwrap();
                assert!(point.is_small_order(), "{encoded} is not small order");
                PublicKey::try_from(&bytes).expect("pkarr accepts small-order keys")
            })
            .collect()
    }

    #[test]
    fn derive_rejects_small_order_keys() {
        let sender = Keypair::random();
        for weak in small_order_keys() {
            assert!(
                ConversationKey::derive(&sender, &weak).is_err(),
                "{weak} accepted"
            );
            assert!(generate_conversation_path(&sender, &weak).is_err());
        }
    }

    #[test]
    fn message_to_small_order_key_is_not_created() {
        let sender = Keypair::random();
        let identity =
            PublicKey::try_from("yryyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy").unwrap();
        assert!(PrivateMessage::new(&sender, &identity, "public secret").is_err());
    }
}
