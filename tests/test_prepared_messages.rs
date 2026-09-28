use anyhow::Result;
use pubky_messenger::{Keypair, PreparedMessage, PrivateMessengerClient, PublicKey};
use pubky_testnet::Testnet;

async fn signed_up(testnet: &Testnet, homeserver: &PublicKey) -> Result<PrivateMessengerClient> {
    let client =
        PrivateMessengerClient::with_client(Keypair::random(), testnet.client_builder().build()?);
    client.sign_up(homeserver, None).await?;
    Ok(client)
}

#[tokio::test]
async fn prepared_publication_survives_restart_and_decrypts_once() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver().await?.public_key();
    let alice = signed_up(&testnet, &homeserver).await?;
    let bob = signed_up(&testnet, &homeserver).await?;
    let prepared = alice.prepare_message(&bob.public_key(), "saved before publication")?;
    let saved = serde_json::to_vec(&prepared)?;
    assert_eq!(alice.request_stats().put.attempts, 0);
    assert_eq!(alice.request_stats().session.attempts, 0);
    alice.publish_message(&prepared).await?;

    let restarted = PrivateMessengerClient::with_client(
        alice.keypair().clone(),
        testnet.client_builder().build()?,
    );
    let restored: PreparedMessage = serde_json::from_slice(&saved)?;
    assert_eq!(restarted.publish_message(&restored).await?, prepared.id());
    assert_eq!(
        restarted.request_stats().put.request_body_bytes,
        prepared.payload().len() as u64
    );
    let received = bob.get_messages(&alice.public_key()).await?;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].content, "saved before publication");
    assert!(received[0].verified);
    let stats = bob.request_stats();
    assert_eq!(stats.get.attempts, 1);
    assert_eq!(
        stats.get.response_body_bytes,
        prepared.payload().len() as u64
    );
    assert!(stats.list.attempts >= 2);
    assert!(stats.list.response_body_bytes > 0);

    restarted
        .delete_message(restored.id(), &bob.public_key())
        .await?;
    assert_eq!(restarted.request_stats().delete.attempts, 1);
    assert!(bob.get_messages(&alice.public_key()).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn concurrent_publication_shares_session_and_stores_one_message() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver().await?.public_key();
    let alice = signed_up(&testnet, &homeserver).await?;
    let bob = signed_up(&testnet, &homeserver).await?;
    let prepared = alice.prepare_message(&bob.public_key(), "concurrent replay")?;
    let results = futures::future::join_all((0..4).map(|_| alice.publish_message(&prepared))).await;
    for result in results {
        assert_eq!(result?, prepared.id());
    }
    assert_eq!(alice.request_stats().session.attempts, 1);
    assert_eq!(alice.request_stats().put.attempts, 4);
    assert_eq!(
        alice.request_stats().put.request_body_bytes,
        (prepared.payload().len() * 4) as u64
    );
    assert_eq!(bob.get_messages(&alice.public_key()).await?.len(), 1);
    assert!(bob.publish_message(&prepared).await.is_err());
    assert_eq!(bob.request_stats().put.attempts, 0);
    Ok(())
}
