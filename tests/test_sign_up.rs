mod common;

use anyhow::Result;
use pubky_messenger::{Keypair, PrivateMessengerClient, PublicKey};
use pubky_testnet::docker_postgres::DockerPostgres;
use pubky_testnet::pubky_homeserver::{
    storage_config::StorageConfigToml, ConfigToml, HomeserverApp, MockDataDir, SignupMode,
};
use pubky_testnet::Testnet;

/// A homeserver this test owns, so dropping it shuts it down
async fn owned_homeserver(testnet: &Testnet, signup_mode: SignupMode) -> Result<HomeserverApp> {
    let mut config = ConfigToml::default_test_config();
    config.general.signup_mode = signup_mode;
    config.general.database_url = Some(DockerPostgres::shared().await.connection_string()?);
    config.pkdns.dht_bootstrap_nodes = Some(testnet.dht_bootstrap_nodes());
    config.storage.backend = StorageConfigToml::InMemory;
    let data_dir = MockDataDir::new(config, Some(pubky_testnet::pubky::Keypair::random()))?;
    HomeserverApp::start_with_mock_data_dir(data_dir).await
}

fn key(homeserver: &HomeserverApp) -> PublicKey {
    homeserver.public_key().into_inner()
}

fn testnet_client(testnet: &Testnet, keypair: Keypair) -> Result<PrivateMessengerClient> {
    let client = testnet.client_builder().build()?;
    Ok(PrivateMessengerClient::with_client(keypair, client))
}

async fn resolved_homeserver(testnet: &Testnet, public_key: &PublicKey) -> Option<String> {
    let homeserver = testnet
        .sdk()
        .ok()?
        .get_homeserver_of(&public_key.into())
        .await
        .ok()??;
    Some(homeserver.z32())
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
    let mut testnet = common::testnet().await?;
    let homeserver = common::homeserver(&mut testnet).await?;
    let keypair = Keypair::random();
    let client = testnet_client(&testnet, keypair.clone())?;

    assert!(client.sign_in().await.is_err());

    let session = client.sign_up(&homeserver, None).await?;
    assert_eq!(session.public_key().z32(), keypair.public_key().to_z32());

    let fresh_client = testnet_client(&testnet, keypair)?;
    fresh_client.sign_in().await?;
    let recipient = Keypair::random().public_key();
    fresh_client.send_message(&recipient, "hello").await?;

    Ok(())
}

#[tokio::test]
async fn test_ensure_session_signs_in_to_existing_account() -> Result<()> {
    let mut testnet = common::testnet().await?;
    let first_homeserver = common::homeserver(&mut testnet).await?;
    let second_homeserver = common::homeserver(&mut testnet).await?;
    let keypair = Keypair::random();

    let client = testnet_client(&testnet, keypair.clone())?;
    client.ensure_session(&first_homeserver, None).await?;

    let restarted = testnet_client(&testnet, keypair)?;
    restarted.ensure_session(&second_homeserver, None).await?;

    let recipient = Keypair::random().public_key();
    restarted.send_message(&recipient, "hello").await?;

    let host = resolved_homeserver(&testnet, &restarted.public_key()).await;
    assert_eq!(host, Some(first_homeserver.to_string()));

    Ok(())
}

#[tokio::test]
async fn test_ensure_session_does_not_sign_up_elsewhere_when_homeserver_is_down() -> Result<()> {
    let mut testnet = common::testnet().await?;
    let first = owned_homeserver(&testnet, SignupMode::Open).await?;
    let first_homeserver = key(&first);
    let second_homeserver = common::homeserver(&mut testnet).await?;
    let keypair = Keypair::random();

    let client = testnet_client(&testnet, keypair.clone())?;
    client.ensure_session(&first_homeserver, None).await?;

    drop(first);

    let restarted = testnet_client(&testnet, keypair)?;
    let result = restarted.ensure_session(&second_homeserver, None).await;
    assert!(result.is_err());

    let host = resolved_homeserver(&testnet, &restarted.public_key()).await;
    assert_eq!(host, Some(first_homeserver.to_string()));

    Ok(())
}

#[tokio::test]
async fn test_ensure_session_passes_signup_token() -> Result<()> {
    let testnet = common::testnet().await?;
    let server = owned_homeserver(&testnet, SignupMode::TokenRequired).await?;
    let homeserver = key(&server);
    let client = testnet_client(&testnet, Keypair::random())?;

    assert!(client.ensure_session(&homeserver, None).await.is_err());

    let error = client
        .sign_up(&homeserver, Some("AAAA-BBBB-CCCC"))
        .await
        .unwrap_err();
    assert!(!error.to_string().contains("AAAA-BBBB-CCCC"), "{error}");

    let admin = server.admin_server().expect("test config enables admin");
    let token = reqwest::Client::new()
        .get(format!(
            "http://{}/generate_signup_token",
            admin.listen_socket()
        ))
        .header("X-Admin-Password", "admin")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    client.ensure_session(&homeserver, Some(&token)).await?;

    Ok(())
}
