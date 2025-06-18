use pkarr::Keypair;
use pubky_messenger::{PrivateMessage, PrivateMessengerClient};

#[test]
fn test_message_encryption_decryption() {
    // Create two keypairs
    let alice_keypair = Keypair::random();
    let bob_keypair = Keypair::random();

    let alice_pubkey = alice_keypair.public_key();
    let bob_pubkey = bob_keypair.public_key();

    // Create a message from Alice to Bob
    let content = "Hello Bob!";
    let message = PrivateMessage::new(&alice_keypair, &bob_pubkey, content).unwrap();

    // Bob decrypts the message
    let decrypted_content = message
        .decrypt_content(&bob_keypair, &alice_pubkey)
        .unwrap();
    let decrypted_sender = message.decrypt_sender(&bob_keypair, &alice_pubkey).unwrap();

    // Verify the content and sender
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_sender, alice_pubkey.to_string());

    // Verify signature
    let verified = message
        .verify_signature(&decrypted_content, &decrypted_sender)
        .unwrap();
    assert!(verified);
}

#[test]
fn test_client_creation() {
    let keypair = Keypair::random();
    let client = PrivateMessengerClient::new(keypair.clone()).unwrap();
    assert_eq!(client.public_key_string(), keypair.public_key().to_string());
}

#[test]
fn test_message_id_generation() {
    let id1 = PrivateMessage::generate_id();
    let id2 = PrivateMessage::generate_id();

    // IDs should be unique
    assert_ne!(id1, id2);

    // IDs should be valid UUIDs
    assert_eq!(id1.len(), 36); // UUID v4 string length
    assert_eq!(id2.len(), 36);
}
