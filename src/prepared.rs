//! Durable publication of one encrypted resource.

use anyhow::{anyhow, ensure, Context, Result};
use ed25519_dalek::Signature;
use pkarr::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::ConversationKey;
use crate::message::PrivateMessage;
use crate::receive::{FetchConfig, RequestBudget, Requests, Transport};

const VERSION: u8 = 1;

/// An encrypted message prepared before network I/O, suitable for a durable outbox.
///
/// Persist this value before publication and keep it unchanged for every retry. Its ID is a
/// transport resource identity, separate from any application request ID in the content.
/// Restored values are validated and authenticated before use. No destination URL is stored.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedMessage {
    version: u8,
    id: String,
    owner: String,
    recipient: String,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl std::fmt::Debug for PreparedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedMessage")
            .field("version", &self.version)
            .field("id", &self.id)
            .field("payload_bytes", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl PreparedMessage {
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn recipient(&self) -> &str {
        &self.recipient
    }
    /// The exact encrypted bytes used as the PUT body on every publication.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn prepare(keypair: &Keypair, recipient: &PublicKey, content: &str) -> Result<Self> {
        let message = PrivateMessage::new(keypair, recipient, content)?;
        let mut prepared = Self {
            version: VERSION,
            id: PrivateMessage::generate_id(),
            owner: keypair.public_key().to_string(),
            recipient: recipient.to_string(),
            payload: serde_json::to_vec(&message)?,
            signature: Vec::new(),
        };
        prepared.signature = keypair
            .sign(prepared.digest().as_bytes())
            .to_bytes()
            .to_vec();
        Ok(prepared)
    }

    fn digest(&self) -> blake3::Hash {
        let mut hash = blake3::Hasher::new();
        hash.update(b"pubky-messenger/prepared-message");
        hash.update(&[self.version]);
        for value in [
            self.id.as_bytes(),
            self.owner.as_bytes(),
            self.recipient.as_bytes(),
            &self.payload,
        ] {
            hash.update(&(value.len() as u64).to_be_bytes());
            hash.update(value);
        }
        hash.finalize()
    }

    /// Authenticate restored metadata and the encrypted payload shape without secrets or I/O.
    ///
    /// Call this before using restored IDs or participants for cleanup or other side effects.
    /// Publication additionally checks the local owner and decrypts and verifies the message.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION,
            "Unsupported prepared message version"
        );
        let owner = PublicKey::try_from(self.owner.as_str()).context("Invalid prepared owner")?;
        ensure!(
            owner.to_string() == self.owner,
            "Prepared owner is not canonical"
        );
        let recipient =
            PublicKey::try_from(self.recipient.as_str()).context("Invalid prepared recipient")?;
        ensure!(
            recipient.to_string() == self.recipient,
            "Prepared recipient is not canonical"
        );
        let id = Uuid::parse_str(&self.id).context("Invalid prepared message ID")?;
        ensure!(
            id.get_version_num() == 4 && id.to_string() == self.id,
            "Invalid prepared message ID"
        );
        let signature =
            Signature::from_slice(&self.signature).context("Invalid prepared signature")?;
        owner
            .verify(self.digest().as_bytes(), &signature)
            .map_err(|_| anyhow!("Prepared message authentication failed"))?;
        let message: PrivateMessage =
            serde_json::from_slice(&self.payload).context("Invalid prepared payload")?;
        ensure!(
            message.signature_bytes.len() == 64,
            "Invalid prepared message signature length"
        );
        Ok(())
    }

    fn destination(&self, keypair: &Keypair) -> Result<String> {
        self.validate()?;
        ensure!(
            self.owner == keypair.public_key().to_string(),
            "Prepared message belongs to another identity"
        );
        let recipient = PublicKey::try_from(self.recipient.as_str())?;
        let key = ConversationKey::derive(keypair, &recipient)?;
        let message: PrivateMessage =
            serde_json::from_slice(&self.payload).context("Invalid prepared payload")?;
        let sender = message
            .decrypt_sender_with(&key)
            .context("Invalid prepared sender")?;
        let content = message
            .decrypt_content_with(&key)
            .context("Invalid prepared content")?;
        ensure!(
            sender == self.owner && message.verify_signature(&content, &sender)?,
            "Invalid prepared message signature"
        );
        Ok(format!(
            "pubky://{}{}{}.json",
            self.owner,
            key.path(),
            self.id
        ))
    }
}

pub(crate) async fn publish<T: Transport>(
    transport: &T,
    permits: &RequestBudget,
    config: &FetchConfig,
    keypair: &Keypair,
    prepared: &PreparedMessage,
) -> Result<String> {
    let url = prepared.destination(keypair)?;
    Requests::new(transport, permits, config)
        .publish(&url, &prepared.payload)
        .await?;
    Ok(prepared.id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clear::clear_messages;
    use crate::receive::{receive_messages, request_permits, FailureReason, FetchFailure};
    use crate::test_server::{keypair, FakeServer, Reply};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn a_saved_message_retries_after_storage_loses_its_response() {
        let alice = keypair(1);
        let bob = keypair(2).public_key();
        let prepared = PreparedMessage::prepare(&alice, &bob, "durable request").unwrap();
        let saved = serde_json::to_vec(&prepared).unwrap();
        let url = prepared.destination(&alice).unwrap();
        let server = FakeServer::default();
        server.reply_put(&url, vec![Reply::StoredThenBroken, Reply::Status(200)]);
        let config = FetchConfig {
            max_attempts: 1,
            ..FetchConfig::default()
        };
        let permits = request_permits(4);
        assert!(publish(&server, &permits, &config, &alice, &prepared)
            .await
            .is_err());

        let restored: PreparedMessage = serde_json::from_slice(&saved).unwrap();
        assert_eq!(
            publish(&server, &permits, &config, &alice, &restored)
                .await
                .unwrap(),
            prepared.id()
        );
        assert_eq!(server.body(&url).as_bytes(), prepared.payload());
        assert_eq!(server.metrics().snapshot().put.attempts, 2);
        assert_eq!(
            server.metrics().snapshot().put.request_body_bytes,
            (prepared.payload().len() * 2) as u64
        );
        let messages = receive_messages(&server, &permits, &config, &alice, &bob)
            .await
            .unwrap();
        assert_eq!(messages.messages.len(), 1);
        assert_eq!(messages.messages[0].content, "durable request");
        assert!(server
            .state
            .lock()
            .unwrap()
            .put_bodies
            .iter()
            .all(|(target, body)| target == &url && body == prepared.payload()));
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_retries_use_one_resource_and_identical_bytes() {
        let alice = keypair(1);
        let bob = keypair(2).public_key();
        let prepared = PreparedMessage::prepare(&alice, &bob, "one resource").unwrap();
        let server = FakeServer::with_latency(Duration::from_millis(50));
        let permits = request_permits(3);
        let config = FetchConfig::default();
        let results = futures::future::join_all(
            (0..8).map(|_| publish(&server, &permits, &config, &alice, &prepared)),
        )
        .await;
        assert!(results
            .iter()
            .all(|result| result.as_ref().unwrap() == prepared.id()));
        let history = receive_messages(&server, &permits, &config, &alice, &bob)
            .await
            .unwrap();
        assert_eq!(history.messages.len(), 1);
        let state = server.state.lock().unwrap();
        assert_eq!(state.peak, 3);
        assert!(state
            .put_bodies
            .iter()
            .all(|(_, body)| body == prepared.payload()));
        assert!(server.metrics().snapshot().queue_wait > Duration::ZERO);
    }

    #[tokio::test]
    async fn restored_values_are_validated_before_requests() {
        let alice = keypair(1);
        let bob = keypair(2).public_key();
        let prepared = PreparedMessage::prepare(&alice, &bob, "bound payload").unwrap();
        let server = FakeServer::default();
        let config = FetchConfig::default();
        let permits = request_permits(4);
        assert!(publish(&server, &permits, &config, &keypair(3), &prepared)
            .await
            .is_err());
        assert!(prepared.validate().is_ok());
        let original = serde_json::to_value(&prepared).unwrap();
        for (field, replacement) in [
            ("version", serde_json::json!(2)),
            ("id", serde_json::json!("not-a-message-id")),
            ("id", serde_json::json!(Uuid::new_v4().to_string())),
            (
                "owner",
                serde_json::json!(keypair(3).public_key().to_string()),
            ),
            (
                "recipient",
                serde_json::json!(keypair(3).public_key().to_string()),
            ),
            ("payload", serde_json::json!([1, 2, 3])),
            ("signature", serde_json::json!([])),
        ] {
            let mut changed = original.clone();
            changed[field] = replacement;
            let restored: PreparedMessage = serde_json::from_value(changed).unwrap();
            assert!(restored.validate().is_err());
            assert!(publish(&server, &permits, &config, &alice, &restored)
                .await
                .is_err());
        }
        assert_eq!(server.state.lock().unwrap().requests, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn publication_retries_transient_failures_and_reports_permanent_statuses() {
        let alice = keypair(1);
        let bob = keypair(2).public_key();
        let config = FetchConfig {
            request_timeout: Duration::from_secs(1),
            ..FetchConfig::default()
        };
        for status in [401, 403, 404] {
            let server = FakeServer::default();
            let prepared = PreparedMessage::prepare(&alice, &bob, "permanent").unwrap();
            let url = prepared.destination(&alice).unwrap();
            server.reply_put(&url, vec![Reply::Status(status)]);
            let error = publish(&server, &request_permits(2), &config, &alice, &prepared)
                .await
                .unwrap_err();
            let failure = error.downcast_ref::<FetchFailure>().unwrap();
            assert_eq!(failure.reason, FailureReason::Status(status));
            assert_eq!(failure.attempts, 1);
        }
        let server = FakeServer::default();
        let prepared = PreparedMessage::prepare(&alice, &bob, "retry").unwrap();
        let url = prepared.destination(&alice).unwrap();
        server.reply_put(
            &url,
            vec![Reply::Hang, Reply::Status(503), Reply::Status(200)],
        );
        let permits = request_permits(2);
        assert!(publish(&server, &permits, &config, &alice, &prepared)
            .await
            .is_ok());
        let stats = server.metrics().snapshot();
        assert_eq!(stats.put.attempts, 3);
        assert_eq!(stats.retries, 2);
        assert_eq!(stats.timeouts, 1);
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_backlog_leaves_capacity_for_foreground_publication() {
        let alice = keypair(1);
        let bob = keypair(2).public_key();
        let mut server = FakeServer::with_latency(Duration::from_millis(50));
        let backlog: Vec<(u64, &str)> = (0..12).map(|i| (i, "old")).collect();
        for url in server.publish(&alice, &bob, &backlog) {
            server.delays.insert(url, Duration::from_secs(1));
        }
        let prepared = PreparedMessage::prepare(&alice, &bob, "foreground").unwrap();
        let config = FetchConfig::default();
        let permits = request_permits(4);
        let foreground = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let start = tokio::time::Instant::now();
            publish(&server, &permits, &config, &alice, &prepared)
                .await
                .unwrap();
            assert_eq!(start.elapsed(), Duration::from_millis(50));
        };
        let (report, ()) = tokio::join!(
            clear_messages(&server, &permits, &config, &alice, &bob),
            foreground
        );
        assert_eq!(report.unwrap().deleted.len(), 12);
        assert!(server.state.lock().unwrap().peak <= 4);
        let stats = server.metrics().snapshot();
        assert_eq!(stats.delete.attempts, 12);
        assert_eq!(stats.put.attempts, 1);
        assert_eq!(stats.list.attempts, 2);
    }
}
