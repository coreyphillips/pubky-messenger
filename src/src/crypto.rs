use anyhow::{anyhow, Result};
use pkarr::{Keypair, PublicKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hex;

/// Convert Ed25519 public key to X25519 public key
pub fn ed25519_public_to_x25519(ed_pub: &[u8; 32]) -> Option<X25519PublicKey> {
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards_point = compressed.decompress()?;
    Some(X25519PublicKey::from(edwards_point.to_montgomery().to_bytes()))
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

/// Generate shared secret for encryption between two keypairs
pub fn generate_shared_secret(keypair: &Keypair, other_pubkey: &PublicKey) -> Result<String> {
    let ed25519_secret = keypair.secret_key();
    let x25519_secret = ed25519_secret_to_x25519(&ed25519_secret);

    let other_pubkey_bytes = other_pubkey.as_bytes();
    if other_pubkey_bytes.len() != 32 {
        return Err(anyhow!("Invalid public key length"));
    }

    let mut other_ed_bytes = [0u8; 32];
    other_ed_bytes.copy_from_slice(other_pubkey_bytes);

    let other_x25519 = ed25519_public_to_x25519(&other_ed_bytes)
        .ok_or_else(|| anyhow!("Failed to convert pubkey to X25519"))?;

    let shared = x25519_secret.diffie_hellman(&other_x25519);
    Ok(hex::encode(shared.as_bytes()))
}

/// Generate deterministic conversation path for two parties
pub fn generate_conversation_path(keypair: &Keypair, other_pubkey: &PublicKey) -> Result<String> {
    let shared_secret = generate_shared_secret(keypair, other_pubkey)?;
    let path_id = blake3::hash(shared_secret.as_bytes()).to_hex();
    Ok(format!("/pub/private_messages/{}/", path_id))
}