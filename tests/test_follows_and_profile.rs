//! The follow and profile calls, which moved to pubky 0.16's session storage and transport URLs,
//! against a local testnet.

mod common;

use anyhow::Result;
use pubky_messenger::{Keypair, PrivateMessengerClient, PublicKey};
use pubky_testnet::Testnet;

async fn signed_up_client(
    testnet: &Testnet,
    homeserver: &PublicKey,
) -> Result<PrivateMessengerClient> {
    let client =
        PrivateMessengerClient::with_client(Keypair::random(), testnet.client_builder().build()?);
    client.sign_up(homeserver, None).await?;
    Ok(client)
}

#[tokio::test]
async fn follows_are_written_listed_and_removed() -> Result<()> {
    let mut testnet = common::testnet().await?;
    let homeserver = common::homeserver(&mut testnet).await?;
    let alice = signed_up_client(&testnet, &homeserver).await?;
    let bob = signed_up_client(&testnet, &homeserver).await?;

    assert!(alice.get_followed_users().await?.is_empty());
    alice.put_follow(&bob.public_key_string()).await?;
    let followed = alice.get_followed_users().await?;
    assert_eq!(
        followed
            .iter()
            .map(|user| user.pubky.as_str())
            .collect::<Vec<_>>(),
        [bob.public_key_string()]
    );
    // Another reader sees the same list, by the owner's key.
    let from_bob = bob
        .get_followed_users_for(&alice.public_key_string())
        .await?;
    assert_eq!(from_bob.len(), 1);
    assert_eq!(from_bob[0].pubky, bob.public_key_string());

    alice.delete_follow(&bob.public_key_string()).await?;
    assert!(alice.get_followed_users().await?.is_empty());
    Ok(())
}

/// A client that never signed in writes a follow by signing in first, once.
#[tokio::test]
async fn a_follow_signs_in_when_there_is_no_session() -> Result<()> {
    let mut testnet = common::testnet().await?;
    let homeserver = common::homeserver(&mut testnet).await?;
    let alice = signed_up_client(&testnet, &homeserver).await?;
    let bob = signed_up_client(&testnet, &homeserver).await?;

    let restored = PrivateMessengerClient::with_client(
        alice.keypair().clone(),
        testnet.client_builder().build()?,
    );
    let (bob_key, alice_key) = (bob.public_key_string(), alice.public_key_string());
    let (first, second) = tokio::join!(
        restored.put_follow(&bob_key),
        restored.put_follow(&alice_key),
    );
    first?;
    second?;
    assert_eq!(restored.get_followed_users().await?.len(), 2);
    Ok(())
}

#[tokio::test]
async fn the_own_profile_is_read_when_published() -> Result<()> {
    let mut testnet = common::testnet().await?;
    let homeserver = common::homeserver(&mut testnet).await?;
    let alice = signed_up_client(&testnet, &homeserver).await?;
    assert!(alice.get_own_profile().await?.is_none());

    let session = testnet
        .sdk()?
        .signer(alice.keypair().clone().into())
        .signin(pubky_testnet::pubky::ClientId::new("test")?)
        .await?;
    session
        .storage()
        .put(
            "/pub/pubky.app/profile.json",
            r#"{"name":"Alice","bio":"testnet","image":null,"status":null}"#,
        )
        .await?;

    let profile = alice.get_own_profile().await?.expect("a published profile");
    assert_eq!(profile.name, "Alice");
    assert_eq!(profile.bio.as_deref(), Some("testnet"));
    Ok(())
}
