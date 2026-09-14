use anyhow::{anyhow, Result};
use futures::future::join_all;
use pkarr::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use tokio::sync::Semaphore;

use crate::crypto::ConversationKey;
use crate::message::DecryptedMessage;
use crate::receive::{
    conversation_directories, decrypt_message, is_message_url, message_urls, outside_conversation,
    FetchConfig, FetchFailure, Requests, Resource, Transport,
};

/// Where a message is published, known from a directory listing before its body is downloaded
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageId {
    /// Public key of the participant whose directory holds the message
    pub publisher: String,
    /// `pubky://` URL of the message, as listed by the publisher's homeserver
    pub url: String,
}

/// Whether a message can change after it has been acknowledged
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangePolicy {
    /// Each message is written once, at a new random name, and never rewritten. This library
    /// only publishes messages that way.
    ///
    /// An acknowledged message is not requested again while it is listed, so a body rewritten
    /// in place is not seen.
    #[default]
    WriteOnce,
    /// Acknowledged messages may be rewritten in place.
    ///
    /// Every acknowledged message still listed is requested again on each discovery,
    /// conditional on the entity tag it was acknowledged at. An unchanged message costs a
    /// request but no body. A changed one is delivered again with `updated` set. A message
    /// acknowledged without an entity tag, because its homeserver sent none, is not rechecked.
    Revalidate,
}

/// Messages a caller has acknowledged in one conversation
///
/// Discovery lists both participants' directories in full on every call and returns the
/// entries this state has not acknowledged. Message names are random, so their order says
/// nothing about when a message was published, and there is no cursor to resume from.
///
/// The state holds one entry per acknowledged message that was still listed at the last
/// discovery. When a listing completes, acknowledgements for messages no longer in it are
/// dropped, so the state never outgrows the conversation as stored. A listing that fails
/// leaves that directory's acknowledgements as they were.
///
/// Delivery is at least once: a message is returned by every discovery until it is
/// acknowledged. Acknowledge after processing, then persist the state by serializing it, for
/// example with `serde_json`. Restore it by deserializing. A state that was not persisted after
/// an acknowledgement redelivers that message.
///
/// The homeserver event feed is not used. It covers every user of one homeserver, and the two
/// participants may use different homeservers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveState {
    change_policy: ChangePolicy,
    /// Entity tag each message was acknowledged at, by publisher and message URL. Tags are
    /// only kept under [`ChangePolicy::Revalidate`].
    acknowledged: BTreeMap<String, BTreeMap<String, Option<String>>>,
}

impl ReceiveState {
    pub fn new(change_policy: ChangePolicy) -> Self {
        Self {
            change_policy,
            acknowledged: BTreeMap::new(),
        }
    }

    pub fn change_policy(&self) -> ChangePolicy {
        self.change_policy
    }

    /// Stop returning `message` from discovery, unless it changes under
    /// [`ChangePolicy::Revalidate`]
    pub fn acknowledge(&mut self, message: &ReceivedMessage) {
        let etag = match self.change_policy {
            ChangePolicy::WriteOnce => None,
            ChangePolicy::Revalidate => message.etag.clone(),
        };
        self.acknowledged
            .entry(message.id.publisher.clone())
            .or_default()
            .insert(message.id.url.clone(), etag);
    }

    pub fn is_acknowledged(&self, id: &MessageId) -> bool {
        self.acknowledged
            .get(&id.publisher)
            .is_some_and(|messages| messages.contains_key(&id.url))
    }

    /// Number of acknowledged messages being tracked
    pub fn len(&self) -> usize {
        self.acknowledged.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Messages found by listing a conversation
#[derive(Debug, Clone)]
pub struct Discovery {
    /// Unacknowledged messages in listing order, the reader's own directory first. Under
    /// [`ChangePolicy::Revalidate`], acknowledged messages to recheck follow them.
    pub pending: Vec<PendingMessage>,
    /// Listings that could not be read, and listed entries that are not files in the
    /// conversation. Neither has anything pending.
    pub failures: Vec<FetchFailure>,
}

/// A listed message whose body has not been retrieved
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingMessage {
    pub id: MessageId,
    /// Entity tag the message was acknowledged at, if it is being revalidated
    pub acknowledged_etag: Option<String>,
}

/// Messages retrieved from a conversation, and whatever could not be retrieved
#[derive(Debug, Clone)]
pub struct ReceivedMessages {
    /// Oldest first, with equal timestamps in the order given, then bodies that could not be
    /// decrypted. Messages deleted since they were listed, and unchanged ones being
    /// revalidated, are left out.
    pub messages: Vec<ReceivedMessage>,
    /// Listings and messages that could not be retrieved. Unretrieved messages stay
    /// unacknowledged, so the next discovery returns them again.
    pub failures: Vec<FetchFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    pub id: MessageId,
    /// `None` if the body is not a message this conversation can decrypt. Acknowledge it too,
    /// or it is downloaded again on every receive.
    pub message: Option<DecryptedMessage>,
    /// Entity tag the homeserver sent with the body
    pub etag: Option<String>,
    /// The message was acknowledged before and its body has changed since
    pub updated: bool,
}

/// List both directories of the conversation and return what `state` has not acknowledged
pub(crate) async fn discover<T: Transport>(
    transport: &T,
    client_permits: &Semaphore,
    config: &FetchConfig,
    keypair: &Keypair,
    other_pubky: &PublicKey,
    state: &mut ReceiveState,
) -> Result<Discovery> {
    let key = ConversationKey::derive(keypair, other_pubky)?;
    let publishers = publishers(keypair, other_pubky, &key);
    if let Some(stranger) = state.acknowledged.keys().find(|stranger| {
        !publishers
            .iter()
            .any(|(publisher, _)| publisher == *stranger)
    }) {
        return Err(anyhow!(
            "Receive state belongs to another conversation: it holds messages published by {}",
            stranger
        ));
    }

    let requests = Requests::new(transport, client_permits, config);
    let listings = join_all(
        publishers
            .iter()
            .map(|(_, directory)| requests.list(directory)),
    )
    .await;

    let revalidate = state.change_policy == ChangePolicy::Revalidate;
    let mut unacknowledged = Vec::new();
    let mut revalidations = Vec::new();
    let mut failures = Vec::new();
    for ((publisher, directory), listing) in publishers.into_iter().zip(listings) {
        let urls = match listing {
            Ok(entries) => {
                let (urls, mut outside) = message_urls(&directory, entries.unwrap_or_default());
                failures.append(&mut outside);
                urls
            }
            Err(failure) => {
                failures.push(failure);
                continue;
            }
        };

        let mut acknowledged = state.acknowledged.remove(&publisher).unwrap_or_default();
        let listed: HashSet<&str> = urls.iter().map(String::as_str).collect();
        acknowledged.retain(|url, _| listed.contains(url.as_str()));

        for url in &urls {
            let id = || MessageId {
                publisher: publisher.clone(),
                url: url.clone(),
            };
            match acknowledged.get(url) {
                None => unacknowledged.push(PendingMessage {
                    id: id(),
                    acknowledged_etag: None,
                }),
                Some(Some(etag)) if revalidate => revalidations.push(PendingMessage {
                    id: id(),
                    acknowledged_etag: Some(etag.clone()),
                }),
                Some(_) => {}
            }
        }

        if !acknowledged.is_empty() {
            state.acknowledged.insert(publisher, acknowledged);
        }
    }

    unacknowledged.append(&mut revalidations);
    Ok(Discovery {
        pending: unacknowledged,
        failures,
    })
}

/// Download and decrypt the bodies of `pending` messages
pub(crate) async fn retrieve<T: Transport>(
    transport: &T,
    client_permits: &Semaphore,
    config: &FetchConfig,
    keypair: &Keypair,
    other_pubky: &PublicKey,
    pending: &[PendingMessage],
) -> Result<ReceivedMessages> {
    let key = ConversationKey::derive(keypair, other_pubky)?;
    let publishers = publishers(keypair, other_pubky, &key);
    let requests = Requests::new(transport, client_permits, config);

    let results = join_all(pending.iter().map(|pending| async {
        // Pending messages may have been stored and restored by the caller
        let MessageId { publisher, url } = &pending.id;
        if !publishers
            .iter()
            .any(|(p, directory)| p == publisher && is_message_url(directory, url))
        {
            return Err(outside_conversation(url.clone()));
        }

        let known = pending.acknowledged_etag.as_deref();
        let (body, etag) = match requests.retrieve(url, known).await? {
            Resource::Found { body, etag } => (body, etag),
            Resource::NotModified | Resource::Missing => return Ok(None),
        };
        // A homeserver may ignore If-None-Match and send the same body again
        if known.is_some() && etag.as_deref() == known {
            return Ok(None);
        }

        Ok(Some(ReceivedMessage {
            id: pending.id.clone(),
            message: decrypt_message(&body, &key),
            etag,
            updated: known.is_some(),
        }))
    }))
    .await;

    let mut messages = Vec::new();
    let mut failures = Vec::new();
    for (position, result) in results.into_iter().enumerate() {
        match result {
            Ok(Some(received)) => messages.push((position, received)),
            Ok(None) => {}
            Err(failure) => failures.push(failure),
        }
    }
    messages.sort_by_key(|(position, received)| {
        let timestamp = received.message.as_ref().map(|m| m.timestamp);
        (timestamp.is_none(), timestamp, *position)
    });

    Ok(ReceivedMessages {
        messages: messages.into_iter().map(|(_, received)| received).collect(),
        failures,
    })
}

/// Each participant's public key and copy of the conversation, the reader's first
fn publishers(
    keypair: &Keypair,
    other_pubky: &PublicKey,
    key: &ConversationKey,
) -> [(String, String); 2] {
    let [mine, theirs] = conversation_directories(keypair, other_pubky, key);
    [
        (keypair.public_key().to_string(), mine),
        (other_pubky.to_string(), theirs),
    ]
}

/// Discover and retrieve in one call
pub(crate) async fn receive_new<T: Transport>(
    transport: &T,
    client_permits: &Semaphore,
    config: &FetchConfig,
    keypair: &Keypair,
    other_pubky: &PublicKey,
    state: &mut ReceiveState,
) -> Result<ReceivedMessages> {
    let discovery = discover(
        transport,
        client_permits,
        config,
        keypair,
        other_pubky,
        state,
    )
    .await?;
    let mut received = retrieve(
        transport,
        client_permits,
        config,
        keypair,
        other_pubky,
        &discovery.pending,
    )
    .await?;

    let mut failures = discovery.failures;
    failures.append(&mut received.failures);
    received.failures = failures;
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::PrivateMessage;
    use crate::receive::{percent_encode, request_permits, FailureReason, MessageFetch};
    use crate::test_server::{directory, entries_outside, keypair, FakeServer, Reply};
    use std::time::Duration;
    use tokio::time::Instant;

    struct Conversation {
        server: FakeServer,
        permits: Semaphore,
        config: FetchConfig,
        alice: Keypair,
        bob: Keypair,
    }

    impl Conversation {
        fn new(page_size: u16) -> Self {
            let config = FetchConfig {
                max_attempts: 1,
                list_page_size: page_size,
                ..FetchConfig::default()
            };
            Self {
                server: FakeServer::with_latency(Duration::from_millis(50)),
                permits: request_permits(config.max_concurrent_requests),
                config,
                alice: keypair(1),
                bob: keypair(2),
            }
        }

        /// Publish from `author`, where `alice` means Alice and anything else Bob
        fn add(&self, alice: bool, name: &str, timestamp: u64, content: &str) -> String {
            let (author, other) = if alice {
                (&self.alice, &self.bob)
            } else {
                (&self.bob, &self.alice)
            };
            self.server
                .add(author, &other.public_key(), name, timestamp, content)
        }

        /// Alice receives
        async fn receive(&self, state: &mut ReceiveState) -> ReceivedMessages {
            receive_new(
                &self.server,
                &self.permits,
                &self.config,
                &self.alice,
                &self.bob.public_key(),
                state,
            )
            .await
            .unwrap()
        }

        async fn discover(&self, state: &mut ReceiveState) -> Discovery {
            discover(
                &self.server,
                &self.permits,
                &self.config,
                &self.alice,
                &self.bob.public_key(),
                state,
            )
            .await
            .unwrap()
        }

        async fn history(&self) -> MessageFetch {
            crate::receive::receive_messages(
                &self.server,
                &self.permits,
                &self.config,
                &self.alice,
                &self.bob.public_key(),
            )
            .await
            .unwrap()
        }

        /// Message requests made, and bodies sent, since the last call
        fn take_counts(&self) -> (usize, usize) {
            let state = self.server.state.lock().unwrap();
            let counts = (state.message_requests, state.bodies_sent);
            drop(state);
            self.server.reset_counts();
            counts
        }
    }

    fn contents(received: &ReceivedMessages) -> Vec<&str> {
        received
            .messages
            .iter()
            .map(|r| r.message.as_ref().unwrap().content.as_str())
            .collect()
    }

    fn acknowledge_all(state: &mut ReceiveState, received: &ReceivedMessages) {
        for message in &received.messages {
            state.acknowledge(message);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unchanged_conversation_downloads_nothing_after_acknowledgement() {
        let c = Conversation::new(1000);
        c.add(true, "a1.json", 1, "from alice");
        c.add(false, "b1.json", 2, "from bob");
        let mut state = ReceiveState::default();

        let first = c.receive(&mut state).await;
        assert_eq!(contents(&first), ["from alice", "from bob"]);
        assert_eq!(c.take_counts(), (2, 2));
        acknowledge_all(&mut state, &first);

        let second = c.receive(&mut state).await;
        assert!(second.messages.is_empty());
        assert!(second.failures.is_empty());
        assert_eq!(c.take_counts(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn new_names_before_between_and_after_seen_ones_are_found_across_pages() {
        let c = Conversation::new(2);
        for name in ["4", "8", "c"] {
            c.add(false, &format!("{}.json", name), 10, name);
        }
        let mut state = ReceiveState::default();
        let first = c.receive(&mut state).await;
        assert_eq!(first.messages.len(), 3);
        acknowledge_all(&mut state, &first);
        c.take_counts();

        // With two entries per page: [0, 4] [6, 8] [c, f]
        c.add(false, "0.json", 20, "first page");
        c.add(false, "6.json", 21, "second page");
        c.add(false, "f.json", 22, "last page");
        let second = c.receive(&mut state).await;

        assert_eq!(
            contents(&second),
            ["first page", "second page", "last page"]
        );
        assert!(second.messages.iter().all(|r| !r.updated));
        assert_eq!(c.take_counts(), (3, 3));
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_published_behind_the_cursor_is_found_by_the_next_discovery() {
        let c = Conversation::new(2);
        for name in ["2", "4", "6", "8"] {
            c.add(false, &format!("{}.json", name), 1, name);
        }
        let bob_directory = directory(&c.bob, &c.alice.public_key());
        let second_page = format!(
            "{}?limit=2&cursor={}",
            bob_directory,
            percent_encode(&format!("{}4.json", bob_directory))
        );
        let (bob, alice) = (c.bob.clone(), c.alice.public_key());
        c.server.after_request(&second_page, move |server| {
            server.add(&bob, &alice, "0.json", 2, "late");
        });
        let mut state = ReceiveState::default();

        let first = c.receive(&mut state).await;
        assert_eq!(first.messages.len(), 4);
        assert_eq!(c.server.attempts(&second_page), 1);
        acknowledge_all(&mut state, &first);

        let second = c.receive(&mut state).await;
        assert_eq!(contents(&second), ["late"]);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_retrievals_and_unacknowledged_messages_are_returned_again() {
        let c = Conversation::new(1000);
        let fails = c.add(false, "1.json", 1, "fails once");
        c.add(false, "2.json", 2, "processed");
        c.add(false, "3.json", 3, "interrupted");
        let body = c.server.body(&fails);
        c.server
            .reply(&fails, vec![Reply::Status(500), Reply::Body(body)]);
        let mut state = ReceiveState::default();

        let first = c.receive(&mut state).await;
        assert_eq!(contents(&first), ["processed", "interrupted"]);
        assert_eq!(first.failures.len(), 1);
        assert_eq!(first.failures[0].url, fails);
        // Processing stops after the first message, before "interrupted" is acknowledged
        state.acknowledge(&first.messages[0]);
        c.take_counts();

        let second = c.receive(&mut state).await;
        assert_eq!(contents(&second), ["fails once", "interrupted"]);
        assert!(second.failures.is_empty());
        assert_eq!(c.take_counts(), (2, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_listing_keeps_acknowledgements_and_delivers_nothing_again() {
        let c = Conversation::new(1000);
        c.add(true, "a.json", 1, "mine");
        c.add(false, "b.json", 2, "theirs");
        let mut state = ReceiveState::default();
        let first = c.receive(&mut state).await;
        acknowledge_all(&mut state, &first);

        let bob_directory = directory(&c.bob, &c.alice.public_key());
        let listing = c.server.body(&bob_directory);
        c.server.reply(&bob_directory, vec![Reply::Status(503)]);
        let during = c.receive(&mut state).await;
        assert!(during.messages.is_empty());
        assert_eq!(during.failures[0].reason, FailureReason::Status(503));
        assert_eq!(state.len(), 2);

        c.server.reply(&bob_directory, vec![Reply::Body(listing)]);
        c.take_counts();
        let after = c.receive(&mut state).await;
        assert!(after.messages.is_empty());
        assert_eq!(c.take_counts(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn restored_state_does_not_download_acknowledged_messages() {
        let c = Conversation::new(1000);
        c.add(true, "a.json", 1, "mine");
        c.add(false, "b.json", 2, "theirs");
        let mut state = ReceiveState::new(ChangePolicy::Revalidate);
        let first = c.receive(&mut state).await;
        acknowledge_all(&mut state, &first);
        let saved = serde_json::to_string(&state).unwrap();

        c.add(false, "c.json", 3, "while stopped");
        let mut restored: ReceiveState = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored, state);
        c.take_counts();

        let received = c.receive(&mut restored).await;
        assert_eq!(contents(&received), ["while stopped"]);
        let state = c.server.state.lock().unwrap();
        assert_eq!(state.bodies_sent, 1);
        assert_eq!(state.not_modified, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn deleted_messages_leave_the_state() {
        let c = Conversation::new(2);
        let urls: Vec<String> = (0..5)
            .map(|i| c.add(i % 2 == 0, &format!("{}.json", i), i, "hello"))
            .collect();
        let mut state = ReceiveState::default();
        let first = c.receive(&mut state).await;
        acknowledge_all(&mut state, &first);
        assert_eq!(state.len(), 5);

        c.server.remove(&urls[0]);
        c.server.remove(&urls[3]);
        let discovery = c.discover(&mut state).await;

        assert!(discovery.pending.is_empty());
        assert_eq!(state.len(), 3);
        for (i, url) in urls.iter().enumerate() {
            let publisher = if i % 2 == 0 { &c.alice } else { &c.bob };
            let id = MessageId {
                publisher: publisher.public_key().to_string(),
                url: url.clone(),
            };
            assert_eq!(state.is_acknowledged(&id), i != 0 && i != 3);
        }

        // Every message deleted, down to the directories
        for url in [&urls[1], &urls[2], &urls[4]] {
            c.server.remove(url);
        }
        c.server.reply(
            &directory(&c.alice, &c.bob.public_key()),
            vec![Reply::Status(404)],
        );
        c.server.reply(
            &directory(&c.bob, &c.alice.public_key()),
            vec![Reply::Status(404)],
        );
        c.discover(&mut state).await;
        assert!(state.is_empty());
        assert_eq!(state, ReceiveState::default());
    }

    #[tokio::test(start_paused = true)]
    async fn a_message_deleted_after_listing_is_neither_delivered_nor_a_failure() {
        let c = Conversation::new(1000);
        let url = c.add(false, "gone.json", 1, "gone");
        let mut state = ReceiveState::default();

        let discovery = c.discover(&mut state).await;
        c.server.remove(&url);
        let received = retrieve(
            &c.server,
            &c.permits,
            &c.config,
            &c.alice,
            &c.bob.public_key(),
            &discovery.pending,
        )
        .await
        .unwrap();

        assert!(received.messages.is_empty());
        assert!(received.failures.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn rewritten_messages_are_redelivered_only_under_revalidate() {
        let c = Conversation::new(1000);
        c.add(false, "1.json", 1, "original");
        let rewritten = c.add(false, "2.json", 2, "original");
        let mut write_once = ReceiveState::new(ChangePolicy::WriteOnce);
        let mut revalidate = ReceiveState::new(ChangePolicy::Revalidate);
        for state in [&mut write_once, &mut revalidate] {
            let first = c.receive(state).await;
            acknowledge_all(state, &first);
        }
        c.take_counts();

        let unchanged = c.receive(&mut revalidate).await;
        assert!(unchanged.messages.is_empty());
        assert_eq!(c.take_counts(), (2, 0));

        let edited = PrivateMessage::new_at(&c.bob, &c.alice.public_key(), "edited", 3).unwrap();
        c.server.reply(
            &rewritten,
            vec![Reply::Body(serde_json::to_string(&edited).unwrap())],
        );

        let concealed = c.receive(&mut write_once).await;
        assert!(concealed.messages.is_empty());
        assert_eq!(c.take_counts(), (0, 0));

        let changed = c.receive(&mut revalidate).await;
        assert_eq!(contents(&changed), ["edited"]);
        assert!(changed.messages[0].updated);
        assert_eq!(c.take_counts(), (2, 1));
        acknowledge_all(&mut revalidate, &changed);

        let settled = c.receive(&mut revalidate).await;
        assert!(settled.messages.is_empty());
        assert_eq!(c.take_counts(), (2, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn undecryptable_bodies_are_delivered_so_they_can_be_acknowledged() {
        let c = Conversation::new(1000);
        let junk = c.add(false, "0.json", 1, "unused");
        c.server
            .reply(&junk, vec![Reply::Body("not a message".to_string())]);
        c.add(false, "1.json", 5, "readable");
        let mut state = ReceiveState::default();

        let first = c.receive(&mut state).await;
        assert_eq!(first.messages.len(), 2);
        assert_eq!(
            first.messages[0].message.as_ref().unwrap().content,
            "readable"
        );
        assert!(first.messages[1].message.is_none());
        assert_eq!(first.messages[1].id.url, junk);
        acknowledge_all(&mut state, &first);
        c.take_counts();

        assert!(c.receive(&mut state).await.messages.is_empty());
        assert_eq!(c.take_counts(), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_identifies_messages_without_downloading_them() {
        let c = Conversation::new(1000);
        let mine = c.add(true, "m.json", 1, "mine");
        let theirs = c.add(false, "t.json", 2, "theirs");
        let mut state = ReceiveState::default();

        let discovery = c.discover(&mut state).await;
        assert_eq!(c.take_counts(), (0, 0));
        let ids: Vec<_> = discovery.pending.iter().map(|p| p.id.clone()).collect();
        assert_eq!(
            ids,
            [
                MessageId {
                    publisher: c.alice.public_key().to_string(),
                    url: mine
                },
                MessageId {
                    publisher: c.bob.public_key().to_string(),
                    url: theirs
                },
            ]
        );

        // A caller that already has the first delivered retrieves only the second
        let received = retrieve(
            &c.server,
            &c.permits,
            &c.config,
            &c.alice,
            &c.bob.public_key(),
            &discovery.pending[1..],
        )
        .await
        .unwrap();
        assert_eq!(contents(&received), ["theirs"]);
        assert_eq!(c.take_counts(), (1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_state_from_another_conversation_is_rejected() {
        let c = Conversation::new(1000);
        let carol = keypair(3);
        c.server
            .add(&carol, &c.alice.public_key(), "c.json", 1, "from carol");
        let mut state = ReceiveState::default();
        let from_carol = receive_new(
            &c.server,
            &c.permits,
            &c.config,
            &c.alice,
            &carol.public_key(),
            &mut state,
        )
        .await
        .unwrap();
        acknowledge_all(&mut state, &from_carol);

        let result = discover(
            &c.server,
            &c.permits,
            &c.config,
            &c.alice,
            &c.bob.public_key(),
            &mut state,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(state.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn listed_entries_outside_the_conversation_are_reported_without_being_requested() {
        let c = Conversation::new(2);
        let served = [
            c.add(true, "0000.json", 1, "mine"),
            c.add(false, "0001.json", 2, "theirs"),
        ];
        let mut outside = entries_outside(&c.bob, &c.alice.public_key());
        outside.sort();
        c.server
            .list_unserved(&directory(&c.bob, &c.alice.public_key()), &outside);
        let expected: Vec<FetchFailure> =
            outside.iter().cloned().map(outside_conversation).collect();
        let mut state = ReceiveState::default();

        let first = c.receive(&mut state).await;
        assert_eq!(contents(&first), ["mine", "theirs"]);
        assert_eq!(first.failures, expected);
        acknowledge_all(&mut state, &first);

        let second = c.receive(&mut state).await;
        assert!(second.messages.is_empty());
        assert_eq!(second.failures, expected);
        assert_eq!(state.len(), 2);
        for url in &outside {
            // Alice's message is also listed in Bob's directory, and is requested only from hers
            let from_own_listing = usize::from(served.contains(url));
            assert_eq!(c.server.attempts(url), from_own_listing, "{}", url);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pending_messages_outside_the_conversation_are_not_requested() {
        let c = Conversation::new(1000);
        let carol = keypair(3);
        let mine = c.add(true, "0000.json", 1, "mine");
        let theirs = c.add(false, "0000.json", 2, "theirs");
        let from_carol = c
            .server
            .add(&carol, &c.alice.public_key(), "0000.json", 3, "carol");
        let pending = |publisher: &Keypair, url: &str| PendingMessage {
            id: MessageId {
                publisher: publisher.public_key().to_string(),
                url: url.to_string(),
            },
            acknowledged_etag: None,
        };
        let forged = [
            pending(&c.bob, &mine),
            pending(&carol, &from_carol),
            pending(&c.bob, "http://127.0.0.1:9/probe"),
        ];
        let mut all = forged.to_vec();
        all.push(pending(&c.bob, &theirs));

        let received = retrieve(
            &c.server,
            &c.permits,
            &c.config,
            &c.alice,
            &c.bob.public_key(),
            &all,
        )
        .await
        .unwrap();

        assert_eq!(contents(&received), ["theirs"]);
        let expected: Vec<FetchFailure> = forged
            .iter()
            .map(|p| outside_conversation(p.id.url.clone()))
            .collect();
        assert_eq!(received.failures, expected);
        assert_eq!(c.take_counts(), (1, 1));
    }

    /// Requests and simulated time for Alice to read a conversation, once with `get_messages`
    /// and once with `receive_new_messages` after everything already listed was acknowledged.
    /// Latency per request is fixed and Tokio's clock is paused, so the numbers repeat exactly.
    /// Print the table with `cargo test --lib receive_request_counts -- --nocapture`.
    #[tokio::test(start_paused = true)]
    async fn receive_request_counts() {
        let rows = [
            // history, messages per participant before, added per participant after
            ("empty", 0, 0),
            ("unchanged", 150, 0),
            ("growing", 150, 5),
        ];
        let mut table = vec![
            "Latency: 50ms per request. Listing pages: 100 entries.".to_string(),
            "| history | method | listing requests | message requests | bodies | elapsed |"
                .to_string(),
            "|---|---|---|---|---|---|".to_string(),
        ];
        let mut counts = Vec::new();

        for (history, before, added) in rows {
            let c = Conversation::new(100);
            for i in 0..before {
                c.add(true, &format!("a{:04}.json", i), i as u64, "mine");
                c.add(false, &format!("b{:04}.json", i), i as u64, "theirs");
            }
            let mut write_once = ReceiveState::new(ChangePolicy::WriteOnce);
            let mut revalidate = ReceiveState::new(ChangePolicy::Revalidate);
            for state in [&mut write_once, &mut revalidate] {
                let received = c.receive(state).await;
                acknowledge_all(state, &received);
            }
            for i in 0..added {
                // Sort before everything already listed
                c.add(true, &format!("0{:04}.json", i), 1000, "new mine");
                c.add(false, &format!("0{:04}.json", i), 1000, "new theirs");
            }

            let methods: [(&str, Option<&mut ReceiveState>); 3] = [
                ("get_messages", None),
                ("receive, WriteOnce", Some(&mut write_once)),
                ("receive, Revalidate", Some(&mut revalidate)),
            ];
            for (method, state) in methods {
                c.server.reset_counts();
                let start = Instant::now();
                let delivered = match state {
                    None => c.history().await.messages.len(),
                    Some(state) => c.receive(state).await.messages.len(),
                };
                let elapsed = start.elapsed();

                let server = c.server.state.lock().unwrap();
                let row = (
                    server.listing_requests,
                    server.message_requests,
                    server.bodies_sent,
                );
                table.push(format!(
                    "| {} | {} | {} | {} | {} | {:?} |",
                    history, method, row.0, row.1, row.2, elapsed
                ));
                counts.push((history, method, row, delivered, elapsed));
            }
        }
        println!("{}", table.join("\n"));

        let ms = Duration::from_millis;
        let expected = [
            // Two directories that do not exist
            ("empty", "get_messages", (2, 0, 0), 0, ms(50)),
            ("empty", "receive, WriteOnce", (2, 0, 0), 0, ms(50)),
            ("empty", "receive, Revalidate", (2, 0, 0), 0, ms(50)),
            // Pages of 100, 50 and none per directory
            ("unchanged", "get_messages", (6, 300, 300), 300, ms(2050)),
            ("unchanged", "receive, WriteOnce", (6, 0, 0), 0, ms(150)),
            ("unchanged", "receive, Revalidate", (6, 300, 0), 0, ms(2050)),
            ("growing", "get_messages", (6, 310, 310), 310, ms(2100)),
            ("growing", "receive, WriteOnce", (6, 10, 10), 10, ms(250)),
            ("growing", "receive, Revalidate", (6, 310, 10), 10, ms(2100)),
        ];
        assert_eq!(counts, expected);
    }
}
