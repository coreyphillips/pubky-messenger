use anyhow::Result;
use pkarr::dns::rdata::RData;
use pubky_messenger::{Keypair, PrivateMessengerClient, PublicKey};
use pubky_testnet::Testnet;

fn testnet_client(testnet: &Testnet, keypair: Keypair) -> Result<PrivateMessengerClient> {
    let client = testnet.client_builder().build()?;
    Ok(PrivateMessengerClient::with_client(keypair, client))
}

async fn resolved_homeserver(testnet: &Testnet, public_key: &PublicKey) -> Option<String> {
    let packet = testnet
        .client_builder()
        .build()
        .ok()?
        .pkarr()
        .resolve_most_recent(public_key)
        .await;
    packet?.resource_records("_pubky").find_map(|rr| match &rr.rdata {
        RData::SVCB(svcb) => Some(svcb.target.to_string()),
        RData::HTTPS(https) => Some(https.0.target.to_string()),
        _ => None,
    })
}

#[test]
fn test_keypair_accessor_returns_client_keypair() -> Result<()> {
    let keypair = Keypair::random();
    let client = PrivateMessengerClient::new(keypair.clone())?;

    assert_eq!(client.keypair().secret_key(), keypair.secret_key());

    Ok(())
}

#[tokio::test]
async fn test_sign_up_makes_new_identity_usable() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver().await?;
    let keypair = Keypair::random();
    let client = testnet_client(&testnet, keypair.clone())?;

    assert!(client.sign_in().await.is_err());

    let session = client.sign_up(&homeserver.public_key(), None).await?;
    assert_eq!(session.pubky(), &keypair.public_key());

    let fresh_client = testnet_client(&testnet, keypair)?;
    fresh_client.sign_in().await?;
    let recipient = Keypair::random().public_key();
    fresh_client.send_message(&recipient, "hello").await?;

    Ok(())
}

#[tokio::test]
async fn test_ensure_session_signs_in_to_existing_account() -> Result<()> {
    let testnet = Testnet::run().await?;
    let first_homeserver = testnet.run_homeserver().await?;
    let second_homeserver = testnet.run_homeserver().await?;
    let keypair = Keypair::random();

    let client = testnet_client(&testnet, keypair.clone())?;
    client
        .ensure_session(&first_homeserver.public_key(), None)
        .await?;

    let restarted = testnet_client(&testnet, keypair)?;
    restarted
        .ensure_session(&second_homeserver.public_key(), None)
        .await?;

    let recipient = Keypair::random().public_key();
    restarted.send_message(&recipient, "hello").await?;

    let host = resolved_homeserver(&testnet, &restarted.public_key()).await;
    assert_eq!(host, Some(first_homeserver.public_key().to_string()));

    Ok(())
}

#[tokio::test]
async fn test_ensure_session_does_not_sign_up_elsewhere_when_homeserver_is_down() -> Result<()> {
    let testnet = Testnet::run().await?;
    let first_homeserver = testnet.run_homeserver().await?;
    let second_homeserver = testnet.run_homeserver().await?;
    let keypair = Keypair::random();

    let client = testnet_client(&testnet, keypair.clone())?;
    client
        .ensure_session(&first_homeserver.public_key(), None)
        .await?;

    first_homeserver.shutdown().await;

    let restarted = testnet_client(&testnet, keypair)?;
    let result = restarted
        .ensure_session(&second_homeserver.public_key(), None)
        .await;
    assert!(result.is_err());

    let host = resolved_homeserver(&testnet, &restarted.public_key()).await;
    assert_eq!(host, Some(first_homeserver.public_key().to_string()));

    Ok(())
}

#[tokio::test]
async fn test_ensure_session_passes_signup_token() -> Result<()> {
    let testnet = Testnet::run().await?;
    let homeserver = testnet.run_homeserver_with_signup_tokens().await?;
    let client = testnet_client(&testnet, Keypair::random())?;

    assert!(client
        .ensure_session(&homeserver.public_key(), None)
        .await
        .is_err());

    let admin = testnet.client_builder().build()?;
    let token = admin
        .get(format!(
            "https://{}/admin/generate_signup_token",
            homeserver.public_key()
        ))
        .header("X-Admin-Password", "admin")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    client
        .ensure_session(&homeserver.public_key(), Some(&token))
        .await?;

    Ok(())
}
