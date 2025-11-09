use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use futures::future::join_all;
use pkarr::{Keypair, PublicKey};
use pubky_common::recovery_file;
use serde::{Deserialize, Serialize};

use crate::crypto::generate_conversation_path;
use crate::message::{DecryptedMessage, PrivateMessage};

/// Profile information from Pubky
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PubkyProfile {
    pub name: String,
    pub bio: Option<String>,
    pub image: Option<String>,
    pub status: Option<String>,
}

/// A user that is being followed
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FollowedUser {
    pub name: Option<String>,
    pub pubky: String,
}

/// Main client for private messaging
pub struct PrivateMessengerClient {
    client: pubky::Client,
    keypair: Keypair,
}

impl PrivateMessengerClient {
    /// Create a new client from a keypair
    pub fn new(keypair: Keypair) -> Result<Self> {
        let client = pubky::Client::builder()
            .build()
            .map_err(|e| anyhow!("Failed to create pubky client: {}", e))?;

        Ok(Self { client, keypair })
    }

    /// Create a new client from a recovery file
    ///
    /// # Parameters
    /// - `recovery_file_bytes`: The bytes of the .pkarr recovery file
    /// - `passphrase`: Optional passphrase to decrypt the file (defaults to empty string)
    pub fn from_recovery_file(
        recovery_file_bytes: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Self> {
        // Use provided passphrase or default to empty string
        let pass = passphrase.unwrap_or("");

        let keypair = recovery_file::decrypt_recovery_file(recovery_file_bytes, pass)
            .map_err(|e| anyhow!("Failed to decrypt recovery file: {:?}", e))?;

        Self::new(keypair)
    }

    /// Create a new client from a 12-word mnemonic recovery phrase
    ///
    /// # Parameters
    /// - `mnemonic_phrase`: The 12-word BIP39 mnemonic phrase
    /// - `passphrase`: Optional passphrase for additional security (defaults to empty string)
    /// - `language`: Optional language for the mnemonic (defaults to English)
    pub fn from_recovery_phrase(
        mnemonic_phrase: &str,
        passphrase: Option<&str>,
        language: Option<Language>,
    ) -> Result<Self> {
        // Use provided language or default to English
        let lang = language.unwrap_or(Language::English);

        // Use provided passphrase or default to empty string
        let pass = passphrase.unwrap_or("");

        // Parse and validate the mnemonic
        let mnemonic = Mnemonic::parse_in(lang, mnemonic_phrase)
            .map_err(|e| anyhow!("Invalid mnemonic phrase: {}", e))?;

        // Convert to seed with passphrase
        let seed = mnemonic.to_seed(pass);

        // Take first 32 bytes as the ed25519 secret key
        let secret_key_bytes: [u8; 32] = seed[..32]
            .try_into()
            .map_err(|_| anyhow!("Failed to extract secret key from seed"))?;

        // Create keypair from secret key
        let keypair = Keypair::from_secret_key(&secret_key_bytes);

        Self::new(keypair)
    }

    /// Sign in to Pubky
    pub async fn sign_in(&self) -> Result<pubky_common::session::Session> {
        self.client
            .signin(&self.keypair)
            .await
            .map_err(|e| anyhow!("Failed to sign in: {}", e))
    }

    /// Send an encrypted message to a recipient
    pub async fn send_message(&self, recipient: &PublicKey, content: &str) -> Result<String> {
        let message = PrivateMessage::new(&self.keypair, recipient, content)?;
        let msg_id = PrivateMessage::generate_id();
        let serialized = serde_json::to_string(&message)?;

        let private_path = generate_conversation_path(&self.keypair, recipient)?;
        let path = format!(
            "pubky://{}{}{}",
            self.keypair.public_key(),
            private_path,
            format!("{}.json", msg_id)
        );

        let response = self.client.put(&path).body(serialized).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to store message: {}", response.status()));
        }

        Ok(msg_id)
    }

    /// Get all messages in a conversation
    pub async fn get_messages(&self, other_pubky: &PublicKey) -> Result<Vec<DecryptedMessage>> {
        let mut all_messages = Vec::new();
        let private_path = generate_conversation_path(&self.keypair, other_pubky)?;

        // Check both user's paths
        let self_path = format!("pubky://{}{}", self.keypair.public_key(), private_path);
        let other_path = format!("pubky://{}{}", other_pubky, private_path);

        let mut urls = Vec::new();

        // Collect URLs from both paths
        if let Ok(list_builder) = self.client.list(&self_path) {
            if let Ok(self_urls) = list_builder.send().await {
                urls.extend(self_urls);
            }
        }

        if let Ok(list_builder) = self.client.list(&other_path) {
            if let Ok(other_urls) = list_builder.send().await {
                urls.extend(other_urls);
            }
        }

        // Process each message
        for url in urls.iter() {
            let response = self.client.get(url).send().await?;
            if response.status().is_success() {
                let response_text = response.text().await?;

                if let Ok(message) = serde_json::from_str::<PrivateMessage>(&response_text) {
                    if let Ok(content) = message.decrypt_content(&self.keypair, other_pubky) {
                        if let Ok(sender) = message.decrypt_sender(&self.keypair, other_pubky) {
                            let verified =
                                message.verify_signature(&content, &sender).unwrap_or(false);

                            all_messages.push(DecryptedMessage {
                                sender,
                                content,
                                timestamp: message.timestamp,
                                verified,
                            });
                        }
                    }
                }
            }
        }

        // Sort by timestamp
        all_messages.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(all_messages)
    }

    /// Get the user's own profile
    pub async fn get_own_profile(&self) -> Result<Option<PubkyProfile>> {
        let profile_url = format!(
            "pubky://{}/pub/pubky.app/profile.json",
            self.keypair.public_key()
        );
        let response = self.client.get(&profile_url).send().await?;

        if response.status().is_success() {
            let profile_data = response.text().await?;
            match serde_json::from_str::<PubkyProfile>(&profile_data) {
                Ok(profile) => Ok(Some(profile)),
                Err(_) => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Get followed users with their profiles
    pub async fn get_followed_users(&self) -> Result<Vec<FollowedUser>> {
        let follows_url = format!(
            "pubky://{}/pub/pubky.app/follows/",
            self.keypair.public_key()
        );
        let response = self.client.get(&follows_url).send().await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let follows_response = response.text().await?;
        let follow_urls: Vec<String> = follows_response
            .lines()
            .filter(|line| !line.is_empty())
            .map(|url| url.to_string())
            .collect();

        // Fetch profiles in parallel
        let profile_futures: Vec<_> = follow_urls
            .iter()
            .map(|follow_url| {
                let url = follow_url.clone();
                async move { self.get_user_profile(&url).await }
            })
            .collect();

        let results = join_all(profile_futures).await;

        let mut users = Vec::new();
        for result in results {
            if let Ok(user) = result {
                users.push(user);
            }
        }

        Ok(users)
    }

    /// Get profile for a specific user
    async fn get_user_profile(&self, follow_url: &str) -> Result<FollowedUser> {
        let pubky_id = follow_url
            .split('/')
            .last()
            .ok_or_else(|| anyhow!("Failed to extract pubky from URL"))?;

        let profile_url = format!("pubky://{}/pub/pubky.app/profile.json", pubky_id);
        let response = self.client.get(&profile_url).send().await?;

        if response.status().is_success() {
            let profile_data = response.text().await?;
            match serde_json::from_str::<PubkyProfile>(&profile_data) {
                Ok(profile) => Ok(FollowedUser {
                    name: Some(profile.name),
                    pubky: pubky_id.to_string(),
                }),
                Err(_) => Ok(FollowedUser {
                    name: None,
                    pubky: pubky_id.to_string(),
                }),
            }
        } else {
            Ok(FollowedUser {
                name: None,
                pubky: pubky_id.to_string(),
            })
        }
    }

    /// Get followed users for a specific pubky
    pub async fn get_followed_users_for(&self, pubky: &str) -> Result<Vec<FollowedUser>> {
        let follows_url = format!("pubky://{}/pub/pubky.app/follows/", pubky);
        let response = self.client.get(&follows_url).send().await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let follows_response = response.text().await?;
        let follow_urls: Vec<String> = follows_response
            .lines()
            .filter(|line| !line.is_empty())
            .map(|url| url.to_string())
            .collect();

        // Fetch profiles in parallel
        let profile_futures: Vec<_> = follow_urls
            .iter()
            .map(|follow_url| {
                let url = follow_url.clone();
                async move { self.get_user_profile(&url).await }
            })
            .collect();

        let results = join_all(profile_futures).await;

        let mut users = Vec::new();
        for result in results {
            if let Ok(user) = result {
                users.push(user);
            }
        }

        Ok(users)
    }

    /// Follow a user by adding them to our follow list
    pub async fn put_follow(&self, target_pubky: &str) -> Result<()> {
        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Create follow data with timestamp
        let follow_data = serde_json::json!({
            "created_at": timestamp
        });

        // Construct the follow URL
        let follow_url = format!(
            "pubky://{}/pub/pubky.app/follows/{}",
            self.keypair.public_key(),
            target_pubky
        );

        // Send PUT request with follow data
        let response = self.client
            .put(&follow_url)
            .body(follow_data.to_string())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to create follow: {}", response.status()));
        }

        Ok(())
    }

    /// Unfollow a user by removing them from our follow list
    pub async fn delete_follow(&self, target_pubky: &str) -> Result<()> {
        // Construct the follow URL
        let follow_url = format!(
            "pubky://{}/pub/pubky.app/follows/{}",
            self.keypair.public_key(),
            target_pubky
        );

        // Send DELETE request
        let response = self.client
            .delete(&follow_url)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to delete follow: {}", response.status()));
        }

        Ok(())
    }

    /// Get the public key of this client
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Get the public key as a string
    pub fn public_key_string(&self) -> String {
        self.keypair.public_key().to_string()
    }

    /// Delete a single message by its ID from a conversation
    pub async fn delete_message(&self, message_id: &str, other_pubky: &PublicKey) -> Result<()> {
        let private_path = generate_conversation_path(&self.keypair, other_pubky)?;
        let url = format!(
            "pubky://{}{}{}",
            self.keypair.public_key(),
            private_path,
            format!("{}.json", message_id)
        );

        let response = self.client.delete(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to delete message: {}", response.status()));
        }

        Ok(())
    }

    /// Delete multiple messages by their IDs from a conversation
    pub async fn delete_messages(
        &self,
        message_ids: Vec<String>,
        other_pubky: &PublicKey,
    ) -> Result<()> {
        let private_path = generate_conversation_path(&self.keypair, other_pubky)?;

        // Create delete futures for all messages
        let delete_futures: Vec<_> = message_ids
            .iter()
            .map(|msg_id| {
                let url = format!(
                    "pubky://{}{}{}",
                    self.keypair.public_key(),
                    private_path,
                    format!("{}.json", msg_id)
                );
                async move { self.client.delete(&url).send().await }
            })
            .collect();

        // Execute all deletions in parallel
        let results = join_all(delete_futures).await;

        // Check for any failures
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(response) if !response.status().is_success() => {
                    return Err(anyhow!(
                        "Failed to delete message {}: {}",
                        message_ids[i],
                        response.status()
                    ));
                }
                Err(e) => {
                    return Err(anyhow!("Failed to delete message {}: {}", message_ids[i], e));
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Clear all sent messages in a conversation with a specific pubky
    pub async fn clear_messages(&self, other_pubky: &PublicKey) -> Result<()> {
        let private_path = generate_conversation_path(&self.keypair, other_pubky)?;
        let self_path = format!("pubky://{}{}", self.keypair.public_key(), private_path);

        // List all messages in the conversation
        let urls = match self.client.list(&self_path) {
            Ok(list_builder) => match list_builder.send().await {
                Ok(urls) => urls,
                Err(_) => {
                    // No messages to clear
                    return Ok(());
                }
            },
            Err(_) => {
                // No messages to clear
                return Ok(());
            }
        };

        // If no messages, return early
        if urls.is_empty() {
            return Ok(());
        }

        // Delete messages in smaller batches to avoid rate limiting
        const BATCH_SIZE: usize = 5;
        for chunk in urls.chunks(BATCH_SIZE) {
            // Create delete futures for this batch
            let delete_futures: Vec<_> = chunk
                .iter()
                .map(|url| async move { self.client.delete(url).send().await })
                .collect();

            // Execute batch deletions in parallel
            let results = join_all(delete_futures).await;

            // Check for any failures
            for (i, result) in results.iter().enumerate() {
                match result {
                    Ok(response) if !response.status().is_success() => {
                        // Retry once on rate limiting
                        if response.status() == 429 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                            let retry = self.client.delete(&chunk[i]).send().await?;
                            if !retry.status().is_success() {
                                return Err(anyhow!(
                                    "Failed to delete message at {} after retry: {}",
                                    chunk[i],
                                    retry.status()
                                ));
                            }
                        } else {
                            return Err(anyhow!(
                                "Failed to delete message at {}: {}",
                                chunk[i],
                                response.status()
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(anyhow!("Failed to delete message at {}: {}", chunk[i], e));
                    }
                    _ => {}
                }
            }

            // Add a small delay between batches to avoid rate limiting
            if chunk.len() == BATCH_SIZE {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
        }

        Ok(())
    }
}
