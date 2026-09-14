use anyhow::{anyhow, Result};
use futures::future::join_all;
use pkarr::{Keypair, PublicKey};
use std::time::Duration;
use tokio::sync::Semaphore;

use crate::crypto::ConversationKey;
use crate::receive::{conversation_directories, message_urls, FetchConfig, Requests, Transport};

/// Delete every message `keypair` has sent in its conversation with `other_pubky`
///
/// Only files directly inside the sender's copy of the conversation are deleted. Any other
/// entry the homeserver lists is not requested, and fails the call once the messages are gone.
pub(crate) async fn clear_messages<T: Transport>(
    transport: &T,
    client_permits: &Semaphore,
    config: &FetchConfig,
    keypair: &Keypair,
    other_pubky: &PublicKey,
) -> Result<()> {
    let key = ConversationKey::derive(keypair, other_pubky)?;
    let [directory, _] = conversation_directories(keypair, other_pubky, &key);

    let entries = Requests::new(transport, client_permits, config)
        .list(&directory)
        .await
        .map_err(|failure| anyhow!("Failed to list messages to clear: {}", failure))?
        .unwrap_or_default();
    let (urls, outside) = message_urls(&directory, entries);

    // Delete messages in smaller batches to avoid rate limiting
    const BATCH_SIZE: usize = 5;
    for chunk in urls.chunks(BATCH_SIZE) {
        let statuses = join_all(chunk.iter().map(|url| transport.delete(url))).await;

        for (url, status) in chunk.iter().zip(statuses) {
            let status = match status {
                // Retry once on rate limiting
                Ok(429) => {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                    transport.delete(url).await
                }
                other => other,
            };
            match status {
                Ok(status) if (200..300).contains(&status) => {}
                Ok(status) => {
                    return Err(anyhow!("Failed to delete message at {}: {}", url, status))
                }
                Err(e) => return Err(anyhow!("Failed to delete message at {}: {}", url, e)),
            }
        }

        // Add a small delay between batches to avoid rate limiting
        if chunk.len() == BATCH_SIZE {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    match outside.first() {
        None => Ok(()),
        Some(failure) => Err(anyhow!(
            "Failed to clear {} listed entr(ies), including {}",
            outside.len(),
            failure
        )),
    }
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
        .await;

        let error = result.unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "Failed to clear {} listed entr(ies), including ",
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
        .await;

        assert!(result.is_err());
        assert!(server.state.lock().unwrap().deleted.is_empty());
    }
}
