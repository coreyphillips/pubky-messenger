use pkarr::Keypair;
use pubky_messenger::{PrivateMessage, PrivateMessengerClient};

#[test]
fn test_message_encryption_decryption() {
    // Create two keypairs
    let alice_keypair = Keypair::random();
    let bob_keypair = Keypair::random();

    let alice_pubky = alice_keypair.public_key();
    let bob_pubky = bob_keypair.public_key();

    // Create a message from Alice to Bob
    let content = "Hello Bob!";
    let message = PrivateMessage::new(&alice_keypair, &bob_pubky, content).unwrap();

    // Bob decrypts the message
    let decrypted_content = message.decrypt_content(&bob_keypair, &alice_pubky).unwrap();
    let decrypted_sender = message.decrypt_sender(&bob_keypair, &alice_pubky).unwrap();

    // Verify the content and sender
    assert_eq!(decrypted_content, content);
    assert_eq!(decrypted_sender, alice_pubky.to_string());

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

#[test]
fn test_messages_encrypted_by_0_3_0_still_decrypt() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/conversation_v0_3_0.json")).unwrap();
    let keypair = |name: &str| {
        let bytes: [u8; 32] = hex::decode(fixture[name].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        Keypair::from_secret_key(&bytes)
    };
    let alice = keypair("alice_secret_key");
    let bob = keypair("bob_secret_key");

    for entry in fixture["messages"].as_array().unwrap() {
        let message: PrivateMessage = serde_json::from_value(entry["message"].clone()).unwrap();
        let author = if entry["author"] == "alice" {
            &alice
        } else {
            &bob
        };

        for (reader, other) in [(&alice, &bob), (&bob, &alice)] {
            let content = message
                .decrypt_content(reader, &other.public_key())
                .unwrap();
            let sender = message.decrypt_sender(reader, &other.public_key()).unwrap();
            assert_eq!(content, entry["content"].as_str().unwrap());
            assert_eq!(sender, author.public_key().to_string());
            assert!(message.verify_signature(&content, &sender).unwrap());
        }
    }
}
