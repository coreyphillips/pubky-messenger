use anyhow::{anyhow, Result};
use futures::future::join_all;
use pkarr::{Keypair, PublicKey};
use std::collections::HashSet;

use crate::crypto::ConversationKey;
use crate::receive::{
    conversation_directories, is_message_url, message_urls, FetchConfig, FetchFailure,
    RequestBudget, Requests, Transport,
};

/// Results of deleting selected messages or clearing the sender's conversation directory
#[derive(Debug, Clone, Default)]
pub struct MessageDeletion {
    /// Message URLs successfully deleted or already absent, in input or listing order
    pub deleted: Vec<String>,
    /// Listings or messages that could not be deleted under the configured request policy
    pub failures: Vec<FetchFailure>,
}

impl MessageDeletion {
    pub(crate) fn into_result(self) -> Result<()> {
        match self.failures.first() {
            None => Ok(()),
            Some(failure) => Err(anyhow!(
                "Failed to delete {} listing(s) or message(s), including {}",
                self.failures.len(),
                failure
            )),
        }
    }
}

/// Delete only the messages selected by the caller, validating every ID before making requests
pub(crate) async fn delete_messages<T: Transport>(
    transport: &T,
    client_permits: &RequestBudget,
    config: &FetchConfig,
    keypair: &Keypair,
    other_pubky: &PublicKey,
    message_ids: &[String],
) -> Result<MessageDeletion> {
    let directory = sent_directory(keypair, other_pubky)?;
    let urls = message_ids
        .iter()
        .map(|id| {
            if !is_message_url(&directory, &format!("{}{}", directory, id)) {
                return Err(anyhow!("Invalid message ID: expected a nonempty file name"));
            }
            Ok(format!("{}{}.json", directory, id))
        })
        .collect::<Result<Vec<_>>>()?;
    let requests = Requests::for_cleanup(transport, client_permits, config);
    Ok(delete_urls(&requests, urls).await)
}

/// Delete every message the sender has stored in this conversation
pub(crate) async fn clear_messages<T: Transport>(
    transport: &T,
    client_permits: &RequestBudget,
    config: &FetchConfig,
    keypair: &Keypair,
    other_pubky: &PublicKey,
) -> Result<MessageDeletion> {
    let directory = sent_directory(keypair, other_pubky)?;
    let requests = Requests::for_cleanup(transport, client_permits, config);
    let entries = match requests.list(&directory).await {
        Ok(entries) => entries.unwrap_or_default(),
        Err(failure) => {
            return Ok(MessageDeletion {
                deleted: Vec::new(),
                failures: vec![failure],
            })
        }
    };
    let (urls, mut outside) = message_urls(&directory, entries);
    let mut deletion = delete_urls(&requests, urls).await;
    outside.append(&mut deletion.failures);
    deletion.failures = outside;
    Ok(deletion)
}

fn sent_directory(keypair: &Keypair, other_pubky: &PublicKey) -> Result<String> {
    let key = ConversationKey::derive(keypair, other_pubky)?;
    let [directory, _] = conversation_directories(keypair, other_pubky, &key);
    Ok(directory)
}

async fn delete_urls<T: Transport>(
    requests: &Requests<'_, T>,
    urls: Vec<String>,
) -> MessageDeletion {
    let mut seen = HashSet::new();
    let urls: Vec<String> = urls
        .into_iter()
        .filter(|url| seen.insert(url.clone()))
        .collect();
    let results = join_all(urls.iter().map(|url| requests.delete(url))).await;
    let mut deletion = MessageDeletion::default();
    for (url, result) in urls.into_iter().zip(results) {
        match result {
            Ok(()) => deletion.deleted.push(url),
            Err(failure) => deletion.failures.push(failure),
        }
    }
    deletion
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive::request_permits;
    use crate::test_server::{directory, entries_outside, keypair, FakeServer, Reply};

    #[tokio::test(start_paused = true)]
    async fn listed_entries_outside_the_conversation_are_not_requested() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        let contents: Vec<String> = (0..7).map(|i| format!("sent {}", i)).collect();
        let messages: Vec<(u64, &str)> = contents
            .iter()
            .enumerate()
            .map(|(i, content)| (i as u64, content.as_str()))
            .collect();
        let mut sent = server.publish(&alice, &bob.public_key(), &messages);
        let received = server.publish(&bob, &alice.public_key(), &[(9, "received")]);
        let outside = entries_outside(&alice, &bob.public_key());
        server.list_unserved(&directory(&alice, &bob.public_key()), &outside);
        // Hostile entries end pages and become cursors
        let config = FetchConfig {
            list_page_size: 2,
            ..FetchConfig::default()
        };

        let result = clear_messages(
            &server,
            &request_permits(4),
            &config,
            &alice,
            &bob.public_key(),
        )
        .await
        .and_then(MessageDeletion::into_result);

        let error = result.unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "Failed to delete {} listing(s) or message(s), including ",
                outside.len()
            )),
            "{}",
            error
        );
        let mut deleted = server.state.lock().unwrap().deleted.clone();
        deleted.sort();
        sent.sort();
        assert_eq!(deleted, sent);
        for url in &outside {
            assert_eq!(server.attempts(url), 0, "{}", url);
        }
        // Bob's copy of his message is among the entries outside Alice's directory
        assert!(outside.contains(&received[0]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_listing_is_an_error_and_deletes_nothing() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        server.publish(&alice, &bob.public_key(), &[(1, "sent")]);
        server.reply(
            &directory(&alice, &bob.public_key()),
            vec![Reply::Status(307)],
        );

        let result = clear_messages(
            &server,
            &request_permits(4),
            &FetchConfig::default(),
            &alice,
            &bob.public_key(),
        )
        .await
        .and_then(MessageDeletion::into_result);

        assert!(result.is_err());
        assert!(server.state.lock().unwrap().deleted.is_empty());
    }

    fn delete_config() -> FetchConfig {
        FetchConfig {
            max_concurrent_requests: 2,
            max_concurrent_requests_per_conversation: 2,
            request_timeout: std::time::Duration::from_secs(1),
            retry_base_delay: std::time::Duration::from_millis(100),
            ..FetchConfig::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn selected_deletions_are_idempotent_and_leave_other_messages() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        let sent = server.publish(&alice, &bob.public_key(), &[(1, "selected"), (2, "keep")]);
        let received = server.publish(&bob, &alice.public_key(), &[(3, "received")]);
        let ids = ["0000".to_string(), "absent".to_string(), "0000".to_string()];
        let expected = vec![
            sent[0].clone(),
            format!("{}absent.json", directory(&alice, &bob.public_key())),
        ];

        for _ in 0..2 {
            let report = delete_messages(
                &server,
                &request_permits(2),
                &delete_config(),
                &alice,
                &bob.public_key(),
                &ids,
            )
            .await
            .unwrap();
            assert_eq!(report.deleted, expected);
            assert!(report.failures.is_empty());
        }

        assert_eq!(
            server.attempts(&sent[0]),
            2,
            "one attempt per unique ID per call"
        );
        assert_eq!(server.attempts(&sent[1]), 0);
        assert_eq!(server.attempts(&received[0]), 0);
        assert_eq!(server.state.lock().unwrap().deleted, [sent[0].clone()]);
    }

    #[tokio::test]
    async fn every_id_is_validated_before_any_delete() {
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        server.publish(&alice, &bob.public_key(), &[(1, "keep")]);

        for invalid in ["", "contains a space", ".", ".."] {
            let ids = ["0000".to_string(), invalid.to_string()];
            let result = delete_messages(
                &server,
                &request_permits(2),
                &delete_config(),
                &alice,
                &bob.public_key(),
                &ids,
            )
            .await;
            assert!(result.is_err());
            assert_eq!(server.state.lock().unwrap().requests, 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deletion_retries_transient_failures_and_reports_every_outcome() {
        use crate::receive::FailureReason;
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        let urls = server.publish(
            &alice,
            &bob.public_key(),
            &[
                (1, "retry"),
                (2, "timeout"),
                (3, "forbidden"),
                (4, "success"),
                (5, "not modified"),
            ],
        );
        server.reply_delete(
            &urls[0],
            vec![Reply::Broken, Reply::Status(503), Reply::Status(200)],
        );
        server.reply_delete(&urls[1], vec![Reply::Hang]);
        server.reply_delete(&urls[2], vec![Reply::Status(403)]);
        server.reply_delete(&urls[4], vec![Reply::Status(304)]);
        let ids: Vec<String> = (0..urls.len()).map(|i| format!("{:04}", i)).collect();
        let permits = request_permits(2);

        let report = delete_messages(
            &server,
            &permits,
            &delete_config(),
            &alice,
            &bob.public_key(),
            &ids,
        )
        .await
        .unwrap();

        assert_eq!(report.deleted, [urls[0].clone(), urls[3].clone()]);
        assert_eq!(
            report.failures,
            [
                FetchFailure {
                    url: urls[1].clone(),
                    attempts: 3,
                    reason: FailureReason::TimedOut
                },
                FetchFailure {
                    url: urls[2].clone(),
                    attempts: 1,
                    reason: FailureReason::Status(403)
                },
                FetchFailure {
                    url: urls[4].clone(),
                    attempts: 1,
                    reason: FailureReason::Status(304)
                },
            ]
        );
        assert_eq!(server.attempts(&urls[0]), 3);
        assert_eq!(permits.available_permits(), 2);
        assert_eq!(server.state.lock().unwrap().in_flight, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limited_deletes_release_capacity_and_honor_retry_after() {
        use std::time::Duration;
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        let urls = server.publish(
            &alice,
            &bob.public_key(),
            &[(1, "limited"), (2, "ready"), (3, "wait too long")],
        );
        server.reply_delete(
            &urls[0],
            vec![
                Reply::RateLimited {
                    retry_after_secs: 3,
                },
                Reply::Status(200),
            ],
        );
        server.reply_delete(
            &urls[2],
            vec![Reply::RateLimited {
                retry_after_secs: 60,
            }],
        );
        let ids: Vec<String> = (0..3).map(|i| format!("{:04}", i)).collect();

        let report = delete_messages(
            &server,
            &request_permits(1),
            &delete_config(),
            &alice,
            &bob.public_key(),
            &ids,
        )
        .await
        .unwrap();

        assert_eq!(report.deleted, urls[..2]);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].attempts, 1);
        let retries = server.starts_of(&urls[0]);
        assert!(retries[1] - retries[0] >= Duration::from_secs(3));
        assert!(server.starts_of(&urls[1])[0] < retries[1]);
    }

    #[tokio::test(start_paused = true)]
    async fn reads_and_deletes_share_the_client_budget() {
        use std::time::Duration;
        let alice = keypair(1);
        let bob = keypair(2);
        let carol = keypair(3);
        let server = FakeServer::with_latency(Duration::from_millis(50));
        let sent: Vec<(u64, &str)> = (0..12).map(|i| (i, "sent")).collect();
        let deleted = server.publish(&alice, &bob.public_key(), &sent);
        let kept = server.publish(&alice, &carol.public_key(), &[(1, "keep")]);
        let config = FetchConfig {
            max_concurrent_requests_per_conversation: 1,
            ..delete_config()
        };
        let permits = request_permits(2);
        let requests = Requests::new(&server, &permits, &config);
        let bob_pk = bob.public_key();

        let (deletion, read) = tokio::join!(
            clear_messages(&server, &permits, &config, &alice, &bob_pk),
            requests.retrieve(&kept[0], None),
        );

        assert_eq!(deletion.unwrap().deleted, deleted);
        assert!(read.is_ok());
        let state = server.state.lock().unwrap();
        assert_eq!(state.peak, 2);
        assert!(state.peak_by_conversation.values().all(|peak| *peak == 1));
        assert_eq!(permits.available_permits(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_deletion_releases_capacity_for_later_cleanup() {
        use std::time::Duration;
        let alice = keypair(1);
        let bob = keypair(2);
        let server = FakeServer::default();
        let urls = server.publish(&alice, &bob.public_key(), &[(1, "slow once")]);
        server.reply_delete(&urls[0], vec![Reply::Hang, Reply::Status(200)]);
        let permits = request_permits(1);
        let config = delete_config();
        let ids = ["0000".to_string()];
        let bob_pk = bob.public_key();

        let cancelled = tokio::time::timeout(
            Duration::from_millis(100),
            delete_messages(&server, &permits, &config, &alice, &bob_pk, &ids),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(permits.available_permits(), 1);
        assert_eq!(server.state.lock().unwrap().in_flight, 0);
        let report = delete_messages(&server, &permits, &config, &alice, &bob_pk, &ids)
            .await
            .unwrap();
        assert_eq!(report.deleted, urls);
        assert!(report.failures.is_empty());
    }
}
