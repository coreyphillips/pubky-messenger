use anyhow::Result;
use pubky_messenger::{
    ChangePolicy, FetchConfig, Keypair, PrivateMessage, PrivateMessengerClient, PublicKey,
    ReceiveState, ReceivedMessages,
};
use pubky_testnet::Testnet;

async fn signed_up_client(
    testnet: &Testnet,
    homeserver: &PublicKey,
) -> Result<PrivateMessengerClient> {
    let keypair = Keypair::random();
    let client = PrivateMessengerClient::with_client(keypair, testnet.client_builder().build()?)
        .with_fetch_config(FetchConfig {
            // Every listing below spans several pages
            list_page_size: 2,
            ..FetchConfig::default()
        });
    client.sign_up(homeserver, None).await?;
    Ok(client)
}

fn contents(received: &ReceivedMessages) -> Vec<String> {
    let mut contents: Vec<String> = received
        .messages
        .iter()
        .map(|r| r.message.as_ref().unwrap().content.clone())
        .collect();
    contents.sort();
    contents
}

fn acknowledge_all(state: &mut ReceiveState, received: &ReceivedMessages) {
    assert!(received.failures.is_empty(), "{:?}", received.failures);
    for message in &received.messages {
        state.acknowledge(message);
    }
}

#[tokio::test]
async fn test_only_unacknowledged_messages_are_received() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver().await?.public_key();
    let alice = signed_up_client(&testnet, &homeserver).await?;
    let bob = signed_up_client(&testnet, &homeserver).await?;
    let mut state = ReceiveState::default();

    let empty = bob
        .receive_new_messages(&alice.public_key(), &mut state)
        .await?;
    assert!(empty.messages.is_empty() && empty.failures.is_empty());

    let mut alice_ids = Vec::new();
    for i in 0..3 {
        let id = alice
            .send_message(&bob.public_key(), &format!("alice {i}"))
            .await?;
        alice_ids.push(id);
    }
    for i in 0..2 {
        bob.send_message(&alice.public_key(), &format!("bob {i}"))
            .await?;
    }

    let first = bob
        .receive_new_messages(&alice.public_key(), &mut state)
        .await?;
    assert_eq!(
        contents(&first),
        ["alice 0", "alice 1", "alice 2", "bob 0", "bob 1"]
    );
    assert!(first
        .messages
        .iter()
        .all(|r| r.message.as_ref().unwrap().verified));
    acknowledge_all(&mut state, &first);

    let unchanged = bob
        .receive_new_messages(&alice.public_key(), &mut state)
        .await?;
    assert!(unchanged.messages.is_empty() && unchanged.failures.is_empty());

    alice.send_message(&bob.public_key(), "alice 3").await?;
    alice.send_message(&bob.public_key(), "alice 4").await?;
    let appended = bob
        .receive_new_messages(&alice.public_key(), &mut state)
        .await?;
    assert_eq!(contents(&appended), ["alice 3", "alice 4"]);
    acknowledge_all(&mut state, &appended);

    // The history API reads the same paged listings
    assert_eq!(bob.get_messages(&alice.public_key()).await?.len(), 7);

    let saved = serde_json::to_string(&state)?;
    let mut restored: ReceiveState = serde_json::from_str(&saved)?;
    let after_restart = bob
        .receive_new_messages(&alice.public_key(), &mut restored)
        .await?;
    assert!(after_restart.messages.is_empty());

    alice
        .delete_message(&alice_ids[0], &bob.public_key())
        .await?;
    let discovery = bob
        .discover_messages(&alice.public_key(), &mut restored)
        .await?;
    assert!(discovery.pending.is_empty() && discovery.failures.is_empty());
    assert_eq!(restored.len(), 6);

    Ok(())
}

#[tokio::test]
async fn test_revalidate_redelivers_a_message_rewritten_in_place() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver().await?.public_key();
    let alice = signed_up_client(&testnet, &homeserver).await?;
    let bob = signed_up_client(&testnet, &homeserver).await?;
    alice.send_message(&bob.public_key(), "first draft").await?;

    let mut write_once = ReceiveState::new(ChangePolicy::WriteOnce);
    let mut revalidate = ReceiveState::new(ChangePolicy::Revalidate);
    let mut url = String::new();
    for state in [&mut write_once, &mut revalidate] {
        let received = bob.receive_new_messages(&alice.public_key(), state).await?;
        assert_eq!(contents(&received), ["first draft"]);
        assert!(received.messages[0].etag.is_some());
        url = received.messages[0].id.url.clone();
        acknowledge_all(state, &received);
    }

    let unchanged = bob
        .discover_messages(&alice.public_key(), &mut revalidate)
        .await?;
    assert_eq!(unchanged.pending.len(), 1);
    let not_modified = bob
        .retrieve_messages(&alice.public_key(), &unchanged.pending)
        .await?;
    assert!(not_modified.messages.is_empty() && not_modified.failures.is_empty());

    let edited = PrivateMessage::new(alice.keypair(), &bob.public_key(), "second draft")?;
    let raw = testnet.client_builder().build()?;
    raw.signin(alice.keypair()).await?;
    raw.put(&url)
        .body(serde_json::to_string(&edited)?)
        .send()
        .await?
        .error_for_status()?;

    let concealed = bob
        .receive_new_messages(&alice.public_key(), &mut write_once)
        .await?;
    assert!(concealed.messages.is_empty());

    let changed = bob
        .receive_new_messages(&alice.public_key(), &mut revalidate)
        .await?;
    assert_eq!(contents(&changed), ["second draft"]);
    assert!(changed.messages[0].updated);
    acknowledge_all(&mut revalidate, &changed);

    let settled = bob
        .receive_new_messages(&alice.public_key(), &mut revalidate)
        .await?;
    assert!(settled.messages.is_empty());

    Ok(())
}
