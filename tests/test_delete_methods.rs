use anyhow::Result;
use pubky_messenger::PrivateMessengerClient;
use std::fs;

// Helper function to load client from pkarr file
async fn load_client(pkarr_file: &str, password: &str) -> Result<PrivateMessengerClient> {
    let recovery_file_bytes = fs::read(pkarr_file)?;
    let client = PrivateMessengerClient::from_recovery_file(&recovery_file_bytes, Some(password))?;
    client.sign_in().await?;
    Ok(client)
}

#[tokio::test]
async fn test_delete_message() -> Result<()> {
    // Load both clients
    let client1 = load_client("p1.pkarr", "password").await?;
    let client2 = load_client("p2.pkarr", "password").await?;

    let client2_pubky = client2.public_key();

    // Get initial message count
    let messages_initial = client1.get_messages(&client2_pubky).await?;
    let initial_count = messages_initial.len();

    // Send a test message from client1 to client2 with unique timestamp marker
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let message_content = format!("Test message to be deleted [{}]", timestamp);
    let message_id = client1.send_message(&client2_pubky, &message_content).await?;

    // Wait a moment for the message to be stored
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Verify message exists by getting all messages
    let messages_before = client1.get_messages(&client2_pubky).await?;
    assert_eq!(
        messages_before.len(),
        initial_count + 1,
        "Should have one more message after sending"
    );

    // Verify our specific message exists
    let our_message_exists = messages_before
        .iter()
        .any(|msg| msg.content == message_content);
    assert!(our_message_exists, "Our message should exist before deletion");

    // Delete the specific message
    client1.delete_message(&message_id, &client2_pubky).await?;

    // Wait a moment for the deletion to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Verify message is deleted
    let messages_after = client1.get_messages(&client2_pubky).await?;
    assert_eq!(
        messages_after.len(),
        initial_count,
        "Should return to initial message count after deletion"
    );

    // Verify the deleted message is not in the list
    let deleted_message_exists = messages_after
        .iter()
        .any(|msg| msg.content == message_content);
    assert!(
        !deleted_message_exists,
        "Deleted message should not exist in the conversation"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_messages() -> Result<()> {
    // Load both clients
    let client1 = load_client("p1.pkarr", "password").await?;
    let client2 = load_client("p2.pkarr", "password").await?;

    let client2_pubky = client2.public_key();

    // Get initial message count
    let messages_initial = client1.get_messages(&client2_pubky).await?;
    let initial_count = messages_initial.len();

    // Generate unique messages with timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();

    // Send multiple test messages with unique identifiers
    let msg1 = format!("Message 1 to delete [{}]", timestamp);
    let msg2 = format!("Message 2 to delete [{}]", timestamp);
    let msg3 = format!("Message 3 to delete [{}]", timestamp);
    let keep_msg = format!("Message to keep [{}]", timestamp);

    let message_ids = vec![
        client1.send_message(&client2_pubky, &msg1).await?,
        client1.send_message(&client2_pubky, &msg2).await?,
        client1.send_message(&client2_pubky, &msg3).await?,
    ];

    // Also send a message that won't be deleted
    client1.send_message(&client2_pubky, &keep_msg).await?;

    // Wait for messages to be stored
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Get current message count
    let messages_before = client1.get_messages(&client2_pubky).await?;
    assert_eq!(
        messages_before.len(),
        initial_count + 4,
        "Should have 4 more messages after sending"
    );

    // Delete multiple messages
    client1.delete_messages(message_ids.clone(), &client2_pubky).await?;

    // Wait for deletions to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Verify messages are deleted
    let messages_after = client1.get_messages(&client2_pubky).await?;
    assert_eq!(
        messages_after.len(),
        initial_count + 1,
        "Should have only the kept message plus initial messages"
    );

    // Verify the message we kept is still there
    let kept_message_exists = messages_after
        .iter()
        .any(|msg| msg.content == keep_msg);
    assert!(
        kept_message_exists,
        "Message that wasn't deleted should still exist"
    );

    // Verify deleted messages are gone
    let deleted_messages = [msg1, msg2, msg3];
    for deleted_content in &deleted_messages {
        let exists = messages_after
            .iter()
            .any(|msg| msg.content == *deleted_content);
        assert!(!exists, "Deleted message '{}' should not exist", deleted_content);
    }

    Ok(())
}

#[tokio::test]
async fn test_clear_messages() -> Result<()> {
    // Load both clients
    let client1 = load_client("p1.pkarr", "password").await?;
    let client2 = load_client("p2.pkarr", "password").await?;

    let client2_pubky = client2.public_key();
    let client1_pubky = client1.public_key();

    // Send several test messages from client1 to client2
    for i in 1..=5 {
        client1.send_message(&client2_pubky, &format!("Message {} from client1", i)).await?;
    }

    // Send messages from client2 to client1 (these should NOT be deleted)
    for i in 1..=3 {
        client2.send_message(&client1_pubky, &format!("Message {} from client2", i)).await?;
    }

    // Get all messages before clearing
    let messages_before = client1.get_messages(&client2_pubky).await?;
    let initial_count = messages_before.len();
    assert!(initial_count >= 5, "Should have at least 5 messages total");

    // Count how many messages are from client1 (sent messages)
    let client1_messages_count = messages_before
        .iter()
        .filter(|msg| msg.sender == client1.public_key_string())
        .count();
    assert!(client1_messages_count >= 5, "Should have at least 5 messages from client1");

    // Clear all messages sent by client1 in the conversation
    client1.clear_messages(&client2_pubky).await?;

    // Get all messages after clearing
    let messages_after = client1.get_messages(&client2_pubky).await?;

    // Verify that client1's sent messages are deleted
    let client1_messages_after = messages_after
        .iter()
        .filter(|msg| msg.sender == client1.public_key_string())
        .count();
    assert_eq!(
        client1_messages_after, 0,
        "All messages sent by client1 should be deleted"
    );

    // Verify that client2's messages are still there (if any)
    let client2_messages_after = messages_after
        .iter()
        .filter(|msg| msg.sender == client2.public_key_string())
        .count();

    // The remaining messages should only be from client2
    assert_eq!(
        messages_after.len(),
        client2_messages_after,
        "Only messages from client2 should remain"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_non_existent_message() -> Result<()> {
    // Load client
    let client1 = load_client("p1.pkarr", "password").await?;
    let client2 = load_client("p2.pkarr", "password").await?;

    let client2_pubky = client2.public_key();

    // Try to delete a non-existent message (should not panic, might return error or succeed silently)
    let fake_message_id = "00000000-0000-0000-0000-000000000000";
    let result = client1.delete_message(fake_message_id, &client2_pubky).await;

    // The operation should complete without panicking
    // It may succeed (no-op) or return an error, both are acceptable
    match result {
        Ok(_) => {
            // Silent success is acceptable for non-existent resources
            assert!(true, "Delete of non-existent message succeeded silently");
        }
        Err(e) => {
            // Error is also acceptable
            println!("Expected error for non-existent message: {}", e);
            assert!(true, "Delete of non-existent message returned error as expected");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_clear_empty_conversation() -> Result<()> {
    // Load clients
    let client1 = load_client("p1.pkarr", "password").await?;

    // Create a random keypair for a conversation that definitely has no messages
    let random_keypair = pkarr::Keypair::random();
    let random_pubky = random_keypair.public_key();

    // Clear messages in an empty conversation (should succeed without error)
    let result = client1.clear_messages(&random_pubky).await;

    assert!(
        result.is_ok(),
        "Clearing an empty conversation should succeed"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_messages_with_empty_list() -> Result<()> {
    // Load client
    let client1 = load_client("p1.pkarr", "password").await?;
    let client2 = load_client("p2.pkarr", "password").await?;

    let client2_pubky = client2.public_key();

    // Try to delete with empty list
    let empty_ids: Vec<String> = vec![];
    let result = client1.delete_messages(empty_ids, &client2_pubky).await;

    assert!(
        result.is_ok(),
        "Deleting with empty list should succeed (no-op)"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_mixed_valid_invalid_ids() -> Result<()> {
    // Load both clients
    let client1 = load_client("p1.pkarr", "password").await?;
    let client2 = load_client("p2.pkarr", "password").await?;

    let client2_pubky = client2.public_key();

    // Send a real message
    let valid_id = client1.send_message(&client2_pubky, "Valid message").await?;

    // Mix valid and invalid IDs
    let mixed_ids = vec![
        valid_id.clone(),
        "00000000-0000-0000-0000-000000000000".to_string(),
        "invalid-id-format".to_string(),
    ];

    // Get message count before
    let messages_before = client1.get_messages(&client2_pubky).await?;
    let initial_count = messages_before.len();

    // Try to delete mixed IDs
    let result = client1.delete_messages(mixed_ids, &client2_pubky).await;

    // Check what happened - the behavior depends on implementation
    match result {
        Ok(_) => {
            // If it succeeded, verify the valid message was deleted
            let messages_after = client1.get_messages(&client2_pubky).await?;
            assert!(
                messages_after.len() < initial_count,
                "Valid message should have been deleted"
            );
        }
        Err(e) => {
            // If it failed, that's also acceptable behavior
            println!("Mixed delete failed as expected: {}", e);
        }
    }

    Ok(())
}