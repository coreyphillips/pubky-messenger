#![allow(dead_code)]

use anyhow::Result;
use pubky_messenger::PublicKey;
use pubky_testnet::docker_postgres::DockerPostgres;
use pubky_testnet::Testnet;

/// A local DHT whose homeservers keep their data in the Postgres that
/// `TEST_PUBKY_CONNECTION_STRING` names, as paykit-rs's tests take it, or else in one Docker
/// Postgres per test binary
pub async fn testnet() -> Result<Testnet> {
    if std::env::var_os("TEST_PUBKY_CONNECTION_STRING").is_some() {
        return Testnet::new().await;
    }
    let postgres = DockerPostgres::shared().await.connection_string()?;
    Testnet::new_with_custom_postgres(postgres).await
}

/// Start another homeserver with open sign-up and return its key
pub async fn homeserver(testnet: &mut Testnet) -> Result<PublicKey> {
    Ok(testnet
        .create_random_homeserver()
        .await?
        .public_key()
        .into_inner())
}
