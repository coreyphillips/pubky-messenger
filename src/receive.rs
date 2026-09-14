use anyhow::Result;
use futures::future::{join_all, BoxFuture};
use pkarr::{Keypair, PublicKey};
use std::fmt;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::error::Elapsed;

use crate::crypto::ConversationKey;
use crate::message::{DecryptedMessage, PrivateMessage};

/// Concurrency limits, deadlines and retry policy for retrieving messages
///
/// Each listing or message request holds a permit from its conversation and one from the
/// client while it is in flight. Permits are released when the attempt completes, times out,
/// fails or is cancelled, and are not held while waiting to retry.
///
/// An attempt that times out, fails before a response arrives, or gets a 429 or 5xx status is
/// retried until `max_attempts` have been made. Retry `n` waits `retry_base_delay * 2^(n-1)`,
/// capped at `max_retry_delay`. A `Retry-After` header in seconds replaces that wait, and if
/// it asks for longer than `max_retry_delay` the request is not retried. Other statuses are
/// not retried. A 404 means the directory or message does not exist and is not a failure.
///
/// Limits and attempts below 1 are treated as 1.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// Requests in flight across every conversation being read by this client
    pub max_concurrent_requests: usize,
    /// Requests in flight for one call that reads a conversation
    pub max_concurrent_requests_per_conversation: usize,
    /// Deadline for one attempt, from sending the request to reading the whole body
    pub request_timeout: Duration,
    /// Attempts per request, including the first
    pub max_attempts: u32,
    /// Wait before the first retry, doubled for each later one
    pub retry_base_delay: Duration,
    /// Longest wait before a retry
    pub max_retry_delay: Duration,
    /// Entries requested per page of a directory listing
    ///
    /// A listing is read until the homeserver returns an empty page, because a homeserver
    /// may return fewer entries than requested before the end.
    pub list_page_size: u16,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 16,
            max_concurrent_requests_per_conversation: 8,
            request_timeout: Duration::from_secs(10),
            max_attempts: 3,
            retry_base_delay: Duration::from_millis(500),
            max_retry_delay: Duration::from_secs(10),
            // Pubky homeservers cap pages at 1000 entries
            list_page_size: 1000,
        }
    }
}

/// Messages read from a conversation, and whatever could not be retrieved
#[derive(Debug, Clone)]
pub struct MessageFetch {
    /// Decrypted messages, oldest first. Messages with equal timestamps keep listing order:
    /// the reader's own directory first, then the other participant's.
    pub messages: Vec<DecryptedMessage>,
    /// Listings and messages that could not be retrieved. If any are present, `messages` is
    /// incomplete.
    pub failures: Vec<FetchFailure>,
}

/// A directory listing or message that could not be retrieved
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchFailure {
    pub url: String,
    /// Attempts made before giving up
    pub attempts: u32,
    /// Why the last attempt failed
    pub reason: FailureReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureReason {
    /// Unsuccessful HTTP status; 429 means rate limited
    Status(u16),
    /// No complete response within `request_timeout`
    TimedOut,
    /// The request failed before a response arrived
    Transport(String),
    /// A listing page did not advance past the previous page, so paging would never end
    ListingStalled,
}

impl fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match &self.reason {
            FailureReason::Status(status) => format!("status {}", status),
            FailureReason::TimedOut => "timed out".to_string(),
            FailureReason::Transport(error) => error.clone(),
            FailureReason::ListingStalled => "listing did not advance".to_string(),
        };
        write!(
            f,
            "{}: {} after {} attempt(s)",
            self.url, reason, self.attempts
        )
    }
}

pub(crate) fn request_permits(limit: usize) -> Semaphore {
    Semaphore::new(limit.clamp(1, Semaphore::MAX_PERMITS))
}

pub(crate) struct HttpResponse {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub etag: Option<String>,
    pub body: String,
}

pub(crate) trait Transport: Sync {
    /// GET `url`, answered with 304 if its entity tag matches `if_none_match`
    fn get<'a>(
        &'a self,
        url: &'a str,
        if_none_match: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpResponse, String>>;
}

impl Transport for pubky::Client {
    fn get<'a>(
        &'a self,
        url: &'a str,
        if_none_match: Option<&'a str>,
    ) -> BoxFuture<'a, Result<HttpResponse, String>> {
        Box::pin(async move {
            let mut request = pubky::Client::get(self, url);
            if let Some(etag) = if_none_match {
                request = request.header("if-none-match", etag);
            }
            let response = request.send().await.map_err(|e| error_chain(&e))?;

            let status = response.status();
            let header = |name| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value.trim().to_string())
            };
            let retry_after = header("retry-after")
                .and_then(|value| value.parse::<u64>().ok())
                .map(Duration::from_secs);
            let etag = header("etag");
            let body = if status.is_success() {
                response.text().await.map_err(|e| error_chain(&e))?
            } else {
                String::new()
            };

            Ok(HttpResponse {
                status: status.as_u16(),
                retry_after,
                etag,
                body,
            })
        })
    }
}

// reqwest's Display omits the cause, such as a failed pkarr resolution
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message = format!("{}: {}", message, cause);
        source = cause.source();
    }
    message
}

/// Read every message in the conversation between `keypair` and `other_pubky`
pub(crate) async fn receive_messages<T: Transport>(
    transport: &T,
    client_permits: &Semaphore,
    config: &FetchConfig,
    keypair: &Keypair,
    other_pubky: &PublicKey,
) -> Result<MessageFetch> {
    let key = ConversationKey::derive(keypair, other_pubky)?;
    let requests = Requests::new(transport, client_permits, config);

    let mut failures = Vec::new();
    let mut urls = Vec::new();
    for listing in join_all(
        conversation_directories(keypair, other_pubky, &key)
            .iter()
            .map(|url| requests.list(url)),
    )
    .await
    {
        match listing {
            Ok(entries) => urls.extend(entries.unwrap_or_default()),
            Err(failure) => failures.push(failure),
        }
    }

    // Decrypt each body as it arrives, because join_all keeps every output until the last
    // request finishes
    let results = join_all(urls.iter().map(|url| async {
        Ok(match requests.retrieve(url, None).await? {
            Resource::Found { body, .. } => decrypt_message(&body, &key),
            Resource::NotModified | Resource::Missing => None,
        })
    }))
    .await;

    let mut messages = Vec::new();
    for (position, result) in results.into_iter().enumerate() {
        match result {
            Ok(Some(message)) => messages.push((position, message)),
            // Deleted after it was listed, or not a message this conversation can decrypt
            Ok(None) => {}
            Err(failure) => failures.push(failure),
        }
    }
    messages.sort_by_key(|(position, message)| (message.timestamp, *position));

    Ok(MessageFetch {
        messages: messages.into_iter().map(|(_, message)| message).collect(),
        failures,
    })
}

/// The reader's copy of the conversation, then the other participant's
pub(crate) fn conversation_directories(
    keypair: &Keypair,
    other_pubky: &PublicKey,
    key: &ConversationKey,
) -> [String; 2] {
    let path = key.path();
    [
        format!("pubky://{}{}", keypair.public_key(), path),
        format!("pubky://{}{}", other_pubky, path),
    ]
}

pub(crate) fn decrypt_message(body: &str, key: &ConversationKey) -> Option<DecryptedMessage> {
    let message = serde_json::from_str::<PrivateMessage>(body).ok()?;
    let content = message.decrypt_content_with(key).ok()?;
    let sender = message.decrypt_sender_with(key).ok()?;
    let verified = message.verify_signature(&content, &sender).unwrap_or(false);

    Some(DecryptedMessage {
        sender,
        content,
        timestamp: message.timestamp,
        verified,
    })
}

pub(crate) enum Resource {
    Found { body: String, etag: Option<String> },
    NotModified,
    Missing,
}

pub(crate) struct Requests<'a, T> {
    transport: &'a T,
    client_permits: &'a Semaphore,
    conversation_permits: Semaphore,
    config: &'a FetchConfig,
}

impl<'a, T: Transport> Requests<'a, T> {
    pub(crate) fn new(
        transport: &'a T,
        client_permits: &'a Semaphore,
        config: &'a FetchConfig,
    ) -> Self {
        Self {
            transport,
            client_permits,
            conversation_permits: request_permits(config.max_concurrent_requests_per_conversation),
            config,
        }
    }

    /// Every entry of the directory at `url`, in the homeserver's order, or `None` if the
    /// directory does not exist
    ///
    /// Entries published while paging may be missed if they sort before the cursor.
    pub(crate) async fn list(&self, url: &str) -> Result<Option<Vec<String>>, FetchFailure> {
        let page_size = self.config.list_page_size.max(1);
        let mut entries: Vec<String> = Vec::new();

        loop {
            let page_url = match entries.last() {
                None => format!("{}?limit={}", url, page_size),
                Some(cursor) => format!(
                    "{}?limit={}&cursor={}",
                    url,
                    page_size,
                    percent_encode(cursor)
                ),
            };
            let page = match self.retrieve(&page_url, None).await? {
                Resource::Found { body, .. } => body,
                Resource::Missing if entries.is_empty() => return Ok(None),
                // Emptied while paging
                Resource::Missing | Resource::NotModified => break,
            };

            let page: Vec<String> = page
                .lines()
                .filter(|line| !line.is_empty())
                .map(String::from)
                .collect();
            match (entries.last(), page.last()) {
                (_, None) => break,
                (Some(cursor), Some(last)) if last <= cursor => {
                    return Err(FetchFailure {
                        url: page_url,
                        attempts: 1,
                        reason: FailureReason::ListingStalled,
                    })
                }
                _ => entries.extend(page),
            }
        }

        Ok(Some(entries))
    }

    /// The resource at `url`, unless its entity tag matches `if_none_match`
    pub(crate) async fn retrieve(
        &self,
        url: &str,
        if_none_match: Option<&str>,
    ) -> Result<Resource, FetchFailure> {
        let max_attempts = self.config.max_attempts.max(1);
        let mut attempts = 0;

        loop {
            attempts += 1;
            let (reason, retry_after) = match self.attempt(url, if_none_match).await {
                Ok(Ok(response)) if (200..300).contains(&response.status) => {
                    return Ok(Resource::Found {
                        body: response.body,
                        etag: response.etag,
                    })
                }
                Ok(Ok(response)) if response.status == 304 => return Ok(Resource::NotModified),
                Ok(Ok(response)) if response.status == 404 => return Ok(Resource::Missing),
                Ok(Ok(response)) => (FailureReason::Status(response.status), response.retry_after),
                Ok(Err(error)) => (FailureReason::Transport(error), None),
                Err(_) => (FailureReason::TimedOut, None),
            };

            let delay = match (&reason, retry_after) {
                (FailureReason::Status(status), _) if !is_retryable(*status) => None,
                (_, Some(requested)) => {
                    Some(requested).filter(|d| *d <= self.config.max_retry_delay)
                }
                _ => Some(self.backoff(attempts)),
            };

            match delay {
                Some(delay) if attempts < max_attempts => tokio::time::sleep(delay).await,
                _ => {
                    return Err(FetchFailure {
                        url: url.to_string(),
                        attempts,
                        reason,
                    })
                }
            }
        }
    }

    async fn attempt(
        &self,
        url: &str,
        if_none_match: Option<&str>,
    ) -> Result<Result<HttpResponse, String>, Elapsed> {
        // Always conversation before client, so a call waiting on its own limit holds no
        // capacity that other conversations could use
        let _conversation = self
            .conversation_permits
            .acquire()
            .await
            .expect("never closed");
        let _client = self.client_permits.acquire().await.expect("never closed");
        tokio::time::timeout(
            self.config.request_timeout,
            self.transport.get(url, if_none_match),
        )
        .await
    }

    fn backoff(&self, attempts: u32) -> Duration {
        let factor = 1u32.checked_shl(attempts - 1).unwrap_or(u32::MAX);
        self.config
            .retry_base_delay
            .saturating_mul(factor)
            .min(self.config.max_retry_delay)
    }
}

fn is_retryable(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

// Homeservers take the cursor as the full URL of the last entry seen
pub(crate) fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{:02X}", byte),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server::{directory, keypair, FakeServer, Reply};
    use tokio::time::Instant;

    fn config(client: usize, per_conversation: usize) -> FetchConfig {
        FetchConfig {
            max_concurrent_requests: client,
            max_concurrent_requests_per_conversation: per_conversation,
            request_timeout: Duration::from_secs(5),
            max_attempts: 3,
            retry_base_delay: Duration::from_secs(1),
            max_retry_delay: Duration::from_secs(10),
            list_page_size: 1000,
        }
    }

    async fn receive(
        server: &FakeServer,
        permits: &Semaphore,
        config: &FetchConfig,
        reader: &Keypair,
        other: &PublicKey,
    ) -> MessageFetch {
        // A leaked permit would otherwise hang the test instead of failing it
        tokio::time::timeout(
            Duration::from_secs(3600),
            receive_messages(server, permits, config, reader, other),
        )
        .await
        .expect("receive stalled")
        .unwrap()
    }

    fn contents(fetch: &MessageFetch) -> Vec<&str> {
        fetch.messages.iter().map(|m| m.content.as_str()).collect()
    }

    fn history(prefix: &str, count: usize) -> Vec<(u64, String)> {
        (0..count)
            .map(|i| (i as u64, format!("{} {}", prefix, i)))
            .collect()
    }

    fn as_refs(messages: &[(u64, String)]) -> Vec<(u64, &str)> {
        messages.iter().map(|(t, c)| (*t, c.as_str())).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn overlapping_requests_stay_within_client_and_conversation_limits() {
        let alice = keypair(1);
        let others: Vec<Keypair> = (10..14).map(keypair).collect();
        let server = FakeServer::with_latency(Duration::from_millis(100));
        for other in &others {
            server.publish(
                &alice,
                &other.public_key(),
                &as_refs(&history("from alice", 15)),
            );
            server.publish(
                other,
                &alice.public_key(),
                &as_refs(&history("to alice", 15)),
            );
        }
        let config = config(6, 4);
        let permits = request_permits(config.max_concurrent_requests);

        let other_keys: Vec<PublicKey> = others.iter().map(Keypair::public_key).collect();
        let fetches = join_all(
            other_keys
                .iter()
                .map(|other| receive(&server, &permits, &config, &alice, other)),
        )
        .await;

        for fetch in &fetches {
            assert_eq!(fetch.messages.len(), 30);
            assert!(fetch.failures.is_empty());
        }
        let state = server.state.lock().unwrap();
        assert_eq!(state.peak, 6, "requests overlap up to the client limit");
        assert_eq!(state.peak_by_conversation.len(), 4);
        assert!(state.peak_by_conversation.values().all(|peak| *peak <= 4));
        assert!(state.peak_by_conversation.values().any(|peak| *peak == 4));
        assert_eq!(state.in_flight, 0);
        assert_eq!(permits.available_permits(), 6);
    }

    #[tokio::test(start_paused = true)]
    async fn equal_timestamps_keep_listing_order_whatever_completes_first() {
        let alice = keypair(1);
        let bob = keypair(2);
        let mut server = FakeServer::default();
        let mut urls = server.publish(
            &alice,
            &bob.public_key(),
            &[(10, "a0"), (20, "a1"), (10, "a2")],
        );
        urls.extend(server.publish(&bob, &alice.public_key(), &[(10, "b0"), (5, "b1")]));
        // Later entries complete first
        for (i, url) in urls.iter().enumerate() {
            server.delays.insert(
                url.clone(),
                Duration::from_millis(100 * (urls.len() - i) as u64),
            );
        }
        let config = config(16, 16);
        let permits = request_permits(16);

        let as_alice = receive(&server, &permits, &config, &alice, &bob.public_key()).await;
        let as_bob = receive(&server, &permits, &config, &bob, &alice.public_key()).await;

        assert_eq!(contents(&as_alice), ["b1", "a0", "a2", "b0", "a1"]);
        assert_eq!(contents(&as_bob), ["b1", "b0", "a0", "a2", "a1"]);
    }

    #[tokio::test(start_paused = true)]
    async fn messages_from_0_3_0_decrypt_from_the_same_path() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/conversation_v0_3_0.json"))
                .unwrap();
        let secret = |name: &str| -> Keypair {
            let bytes: [u8; 32] = hex::decode(fixture[name].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            Keypair::from_secret_key(&bytes)
        };
        let alice = secret("alice_secret_key");
        let bob = secret("bob_secret_key");
        let path = fixture["conversation_path"].as_str().unwrap();
        assert_eq!(
            ConversationKey::derive(&alice, &bob.public_key())
                .unwrap()
                .path(),
            path
        );
        assert_eq!(
            ConversationKey::derive(&bob, &alice.public_key())
                .unwrap()
                .path(),
            path
        );

        let server = FakeServer::default();
        let mut expected = Vec::new();
        for (i, entry) in fixture["messages"].as_array().unwrap().iter().enumerate() {
            let author = if entry["author"] == "alice" {
                &alice
            } else {
                &bob
            };
            let directory = format!("pubky://{}{}", author.public_key(), path);
            let url = format!("{}{}.json", directory, i);
            server.reply(&directory, vec![Reply::Body(url.clone())]);
            server.reply(&url, vec![Reply::Body(entry["message"].to_string())]);
            expected.push((
                author.public_key().to_string(),
                entry["content"].as_str().unwrap(),
            ));
        }
        let permits = request_permits(16);

        for (reader, other) in [(&alice, &bob), (&bob, &alice)] {
            let fetch = receive(
                &server,
                &permits,
                &config(16, 8),
                reader,
                &other.public_key(),
            )
            .await;
            let mut received: Vec<_> = fetch
                .messages
                .iter()
                .map(|m| {
                    assert!(m.verified);
                    (m.sender.clone(), m.content.as_str())
                })
                .collect();
            received.sort();
            let mut expected = expected.clone();
            expected.sort();
            assert_eq!(received, expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tampered_signatures_are_reported_unverified() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        let urls = server.publish(
            &alice,
            &bob.public_key(),
            &[(1, "intact"), (2, "bad signature"), (3, "moved")],
        );

        let tamper = |url: &str, change: &dyn Fn(&mut PrivateMessage)| {
            let mut message: PrivateMessage = serde_json::from_str(&server.body(url)).unwrap();
            change(&mut message);
            server.reply(
                url,
                vec![Reply::Body(serde_json::to_string(&message).unwrap())],
            );
        };
        tamper(&urls[1], &|m| m.signature_bytes[0] ^= 1);
        tamper(&urls[2], &|m| m.timestamp = 0);

        let fetch = receive(
            &server,
            &request_permits(4),
            &config(4, 4),
            &bob,
            &alice.public_key(),
        )
        .await;

        let verified: Vec<_> = fetch
            .messages
            .iter()
            .map(|m| (m.content.as_str(), m.verified))
            .collect();
        assert_eq!(
            verified,
            [("moved", false), ("intact", true), ("bad signature", false)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timed_out_attempts_release_capacity_and_retry() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::with_latency(Duration::from_millis(100));
        let urls = server.publish(
            &alice,
            &bob.public_key(),
            &[(1, "slow once"), (2, "never arrives"), (3, "prompt")],
        );
        let slow_once = server.body(&urls[0]);
        server.reply(&urls[0], vec![Reply::Hang, Reply::Body(slow_once)]);
        server.reply(&urls[1], vec![Reply::Hang]);
        // A single permit: an attempt that kept it after timing out would stall everything else
        let permits = request_permits(1);

        let fetch = receive(&server, &permits, &config(1, 1), &alice, &bob.public_key()).await;

        assert_eq!(contents(&fetch), ["slow once", "prompt"]);
        assert_eq!(
            fetch.failures,
            [FetchFailure {
                url: urls[1].clone(),
                attempts: 3,
                reason: FailureReason::TimedOut
            }]
        );
        assert_eq!(server.attempts(&urls[0]), 2);
        assert_eq!(permits.available_permits(), 1);
        assert_eq!(server.state.lock().unwrap().in_flight, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_a_receive_releases_capacity() {
        let alice = keypair(1);
        let bob = keypair(2);
        let carol = keypair(3);
        let server = FakeServer::with_latency(Duration::from_millis(100));
        server.publish(&alice, &bob.public_key(), &[(1, "stuck")]);
        server.reply(&directory(&alice, &bob.public_key()), vec![Reply::Hang]);
        server.reply(&directory(&bob, &alice.public_key()), vec![Reply::Hang]);
        server.publish(&alice, &carol.public_key(), &[(1, "hello carol")]);
        let config = FetchConfig {
            request_timeout: Duration::from_secs(3600),
            ..config(2, 2)
        };
        let permits = request_permits(2);

        let cancelled = tokio::time::timeout(
            Duration::from_secs(1),
            receive_messages(&server, &permits, &config, &alice, &bob.public_key()),
        )
        .await;

        assert!(cancelled.is_err());
        assert_eq!(permits.available_permits(), 2);
        assert_eq!(server.state.lock().unwrap().in_flight, 0);
        let fetch = receive(&server, &permits, &config, &alice, &carol.public_key()).await;
        assert_eq!(contents(&fetch), ["hello carol"]);
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limited_requests_wait_without_holding_capacity() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::with_latency(Duration::from_millis(100));
        let urls = server.publish(
            &alice,
            &bob.public_key(),
            &[(1, "limited"), (2, "unaffected"), (3, "gave up")],
        );
        let limited = server.body(&urls[0]);
        server.reply(
            &urls[0],
            vec![
                Reply::RateLimited {
                    retry_after_secs: 3,
                },
                Reply::Body(limited),
            ],
        );
        server.reply(
            &urls[2],
            vec![Reply::RateLimited {
                retry_after_secs: 60,
            }],
        );
        let permits = request_permits(1);

        let fetch = receive(&server, &permits, &config(1, 1), &alice, &bob.public_key()).await;

        assert_eq!(contents(&fetch), ["limited", "unaffected"]);
        assert_eq!(
            fetch.failures,
            [FetchFailure {
                url: urls[2].clone(),
                attempts: 1,
                reason: FailureReason::Status(429)
            }],
            "Retry-After beyond max_retry_delay is not retried"
        );
        let limited = server.starts_of(&urls[0]);
        let unaffected = server.starts_of(&urls[1]);
        assert_eq!(limited.len(), 2);
        assert!(
            unaffected[0] < limited[1],
            "capacity was used while waiting to retry"
        );
        assert!(limited[1] - limited[0] >= Duration::from_millis(3100));
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failures_follow_the_retry_policy_and_are_reported() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::with_latency(Duration::from_millis(100));
        let urls = server.publish(
            &alice,
            &bob.public_key(),
            &[
                (1, "server error"),
                (2, "forbidden"),
                (3, "broken"),
                (4, "deleted"),
                (5, "fine"),
            ],
        );
        server.reply(&urls[0], vec![Reply::Status(500)]);
        server.reply(&urls[1], vec![Reply::Status(403)]);
        server.reply(
            &urls[2],
            vec![Reply::Broken, Reply::Broken, Reply::Status(502)],
        );
        server.remove(&urls[3]);
        let bob_directory = directory(&bob, &alice.public_key());
        server.reply(&bob_directory, vec![Reply::Status(503)]);

        let fetch = receive(
            &server,
            &request_permits(8),
            &config(8, 8),
            &alice,
            &bob.public_key(),
        )
        .await;

        assert_eq!(contents(&fetch), ["fine"]);
        let failure = |url: &String, attempts, reason| FetchFailure {
            url: url.clone(),
            attempts,
            reason,
        };
        assert_eq!(
            fetch.failures,
            [
                failure(
                    &format!("{}?limit=1000", bob_directory),
                    3,
                    FailureReason::Status(503)
                ),
                failure(&urls[0], 3, FailureReason::Status(500)),
                failure(&urls[1], 1, FailureReason::Status(403)),
                failure(&urls[2], 3, FailureReason::Status(502)),
            ]
        );
        let starts = server.starts_of(&urls[0]);
        assert_eq!(starts[1] - starts[0], Duration::from_millis(1100));
        assert_eq!(starts[2] - starts[1], Duration::from_millis(2100));
    }

    #[tokio::test(start_paused = true)]
    async fn listings_are_read_until_an_empty_page() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        server.publish(
            &alice,
            &bob.public_key(),
            &as_refs(&history("from alice", 5)),
        );
        server.publish(&bob, &alice.public_key(), &[(9, "from bob")]);
        let config = FetchConfig {
            list_page_size: 2,
            ..config(4, 4)
        };

        let fetch = receive(
            &server,
            &request_permits(4),
            &config,
            &alice,
            &bob.public_key(),
        )
        .await;

        assert_eq!(fetch.messages.len(), 6);
        assert!(fetch.failures.is_empty());
        // Alice's pages hold 2, 2, 1 and 0 entries, Bob's 1 and 0
        assert_eq!(server.state.lock().unwrap().listing_requests, 6);
    }

    #[tokio::test(start_paused = true)]
    async fn a_listing_that_ignores_its_cursor_fails_instead_of_paging_forever() {
        let alice = keypair(1);
        let bob = keypair(2);
        let mut server = FakeServer::default();
        server.ignores_cursor = true;
        server.publish(&alice, &bob.public_key(), &[(1, "a"), (2, "b")]);
        let config = FetchConfig {
            list_page_size: 2,
            ..config(4, 4)
        };

        let fetch = receive(
            &server,
            &request_permits(4),
            &config,
            &alice,
            &bob.public_key(),
        )
        .await;

        assert!(fetch.messages.is_empty());
        assert_eq!(fetch.failures.len(), 1);
        assert_eq!(fetch.failures[0].reason, FailureReason::ListingStalled);
    }

    #[tokio::test(start_paused = true)]
    async fn missing_directories_are_an_empty_conversation() {
        let server = FakeServer::with_latency(Duration::from_millis(100));

        let fetch = receive(
            &server,
            &request_permits(4),
            &config(4, 4),
            &keypair(1),
            &keypair(2).public_key(),
        )
        .await;

        assert!(fetch.messages.is_empty());
        assert!(fetch.failures.is_empty());
    }

    /// Simulated elapsed time and request concurrency for several history sizes, with a fixed
    /// latency per request. Tokio's clock is paused, so the numbers exclude CPU time and repeat
    /// exactly. Run with `cargo test --lib receive_latency_report -- --ignored --nocapture`.
    #[tokio::test(start_paused = true)]
    #[ignore]
    async fn receive_latency_report() {
        let latency = Duration::from_millis(50);
        let alice = keypair(1);
        let bob = keypair(2);
        let strategies = [
            ("sequential, as in 0.3.0", config(1, 1)),
            ("FetchConfig::default()", FetchConfig::default()),
        ];

        println!("Injected latency: {:?} per request", latency);
        println!("| messages | strategy | requests | peak in flight | elapsed |");
        println!("|---|---|---|---|---|");
        for size in [10, 50, 200] {
            let server = FakeServer::with_latency(latency);
            server.publish(
                &alice,
                &bob.public_key(),
                &as_refs(&history("from alice", size / 2)),
            );
            server.publish(
                &bob,
                &alice.public_key(),
                &as_refs(&history("from bob", size / 2)),
            );

            for (name, config) in &strategies {
                server.reset_counts();
                let permits = request_permits(config.max_concurrent_requests);
                let start = Instant::now();
                let fetch = receive(&server, &permits, config, &alice, &bob.public_key()).await;
                let elapsed = start.elapsed();
                assert_eq!(fetch.messages.len(), size);

                let state = server.state.lock().unwrap();
                println!(
                    "| {} | {} | {} | {} | {:?} |",
                    size, name, state.requests, state.peak, elapsed
                );
            }
        }
    }

    /// CPU time to decrypt and verify a history, deriving the conversation key per message as
    /// 0.3.0 did versus once per receive. No network is involved. Run with
    /// `cargo test --release --lib key_derivation_report -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn key_derivation_report() {
        use std::time::Instant;

        let alice = keypair(1);
        let bob = keypair(2);
        let size = 200;
        let rounds = 20;
        let bodies: Vec<PrivateMessage> = (0..size)
            .map(|i| {
                PrivateMessage::new_at(&bob, &alice.public_key(), "a short message", i).unwrap()
            })
            .collect();

        let per_message = || {
            let _path = ConversationKey::derive(&alice, &bob.public_key())
                .unwrap()
                .path();
            for message in &bodies {
                let content = message.decrypt_content(&alice, &bob.public_key()).unwrap();
                let sender = message.decrypt_sender(&alice, &bob.public_key()).unwrap();
                assert!(message.verify_signature(&content, &sender).unwrap());
            }
        };
        let once = || {
            let key = ConversationKey::derive(&alice, &bob.public_key()).unwrap();
            let _path = key.path();
            for message in &bodies {
                let content = message.decrypt_content_with(&key).unwrap();
                let sender = message.decrypt_sender_with(&key).unwrap();
                assert!(message.verify_signature(&content, &sender).unwrap());
            }
        };
        let derive_only = || {
            let _ = ConversationKey::derive(&alice, &bob.public_key()).unwrap();
        };

        let fastest = |run: &dyn Fn(), repeat: u32| {
            (0..rounds)
                .map(|_| {
                    let start = Instant::now();
                    for _ in 0..repeat {
                        run();
                    }
                    start.elapsed() / repeat
                })
                .min()
                .unwrap()
        };

        let derivation = fastest(&derive_only, 100);
        let before = fastest(&per_message, 1);
        let after = fastest(&once, 1);
        println!(
            "| {} messages, fastest of {} rounds | CPU time |",
            size, rounds
        );
        println!("|---|---|");
        println!("| one key derivation | {:?} |", derivation);
        println!(
            "| derive per message ({} derivations) | {:?} |",
            2 * size + 1,
            before
        );
        println!("| derive once (1 derivation) | {:?} |", after);
        println!(
            "| saved per message | {:?} |",
            before.saturating_sub(after) / size as u32
        );
    }
}
