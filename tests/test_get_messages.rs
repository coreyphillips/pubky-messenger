use anyhow::Result;
use pubky_messenger::{FailureReason, FetchConfig, Keypair, PrivateMessengerClient, PublicKey};
use pubky_testnet::Testnet;
use std::time::Duration;

async fn signed_up_client(
    testnet: &Testnet,
    homeserver: &PublicKey,
) -> Result<PrivateMessengerClient> {
    let keypair = Keypair::random();
    let client = PrivateMessengerClient::with_client(keypair, testnet.client_builder().build()?);
    client.sign_up(homeserver, None).await?;
    Ok(client)
}

#[tokio::test]
async fn test_both_participants_read_the_whole_conversation_in_order() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver().await?.public_key();
    let alice = signed_up_client(&testnet, &homeserver).await?;
    let bob = signed_up_client(&testnet, &homeserver).await?;

    assert!(alice.get_messages(&bob.public_key()).await?.is_empty());

    for i in 0..12 {
        let (author, reader) = if i % 3 == 0 {
            (&bob, &alice)
        } else {
            (&alice, &bob)
        };
        author
            .send_message(&reader.public_key(), &format!("message {i}"))
            .await?;
    }

    let config = FetchConfig {
        max_concurrent_requests: 4,
        max_concurrent_requests_per_conversation: 3,
        ..FetchConfig::default()
    };
    let alice = alice.with_fetch_config(config);
    let as_alice = alice.get_messages(&bob.public_key()).await?;
    let as_bob = bob.get_messages(&alice.public_key()).await?;

    for messages in [&as_alice, &as_bob] {
        assert_eq!(messages.len(), 12);
        assert!(messages.iter().all(|m| m.verified));
        assert!(messages
            .windows(2)
            .all(|w| w[0].timestamp <= w[1].timestamp));
        let mut contents: Vec<_> = messages.iter().map(|m| m.content.clone()).collect();
        contents.sort();
        let mut expected: Vec<_> = (0..12).map(|i| format!("message {i}")).collect();
        expected.sort();
        assert_eq!(contents, expected);
    }
    let bob_sent = as_alice
        .iter()
        .filter(|m| m.sender == bob.public_key_string())
        .count();
    assert_eq!(bob_sent, 4);

    Ok(())
}

#[tokio::test]
async fn test_unreachable_participant_is_an_error_not_an_empty_conversation() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver().await?.public_key();
    let alice = signed_up_client(&testnet, &homeserver)
        .await?
        .with_fetch_config(FetchConfig {
            max_attempts: 1,
            request_timeout: Duration::from_secs(30),
            ..FetchConfig::default()
        });
    let nobody = Keypair::random().public_key();
    alice.send_message(&nobody, "are you there?").await?;

    assert!(alice.get_messages(&nobody).await.is_err());

    let fetch = alice.fetch_messages(&nobody).await?;
    assert_eq!(fetch.messages.len(), 1);
    assert_eq!(fetch.messages[0].content, "are you there?");
    assert_eq!(fetch.failures.len(), 1);
    assert!(fetch.failures[0]
        .url
        .starts_with(&format!("pubky://{nobody}/")));
    assert!(matches!(
        fetch.failures[0].reason,
        FailureReason::Transport(_)
    ));

    Ok(())
}
