use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use futures::future::join_all;
use pkarr::{Keypair, PublicKey};
use pubky::{ClientId, IntoPubkyResource, Pubky, PubkyHttpClient, PubkySession, SessionInfo};
use pubky_common::recovery_file;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::clear::{clear_messages, delete_messages, MessageDeletion};
use crate::incremental::{
    discover, receive_new, retrieve, Discovery, PendingMessage, ReceiveState, ReceivedMessages,
};
use crate::message::DecryptedMessage;
use crate::metrics::RequestStats;
use crate::prepared::{publish, PreparedMessage};
use crate::receive::{
    receive_messages, request_permits, FetchConfig, MessageFetch, PubkyTransport, RequestBudget,
    Transport,
};

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

/// Names this library to homeservers, which record the client holding each session grant
const CLIENT_ID: &str = "pubky-messenger";

/// Main client for private messaging
pub struct PrivateMessengerClient {
    client: PubkyHttpClient,
    /// Session from the last sign-in or sign-up, for profile and follow writes
    session: Mutex<Option<PubkySession>>,
    /// Reads conversations and clears them, which homeservers must not redirect elsewhere
    transport: PubkyTransport,
    keypair: Keypair,
    fetch_config: FetchConfig,
    request_permits: RequestBudget,
}

impl PrivateMessengerClient {
    /// Create a new client from a keypair, using a default mainnet pubky client
    pub fn new(keypair: Keypair) -> Result<Self> {
        let client =
            PubkyHttpClient::new().map_err(|e| anyhow!("Failed to create pubky client: {}", e))?;

        Ok(Self::with_client(keypair, client))
    }

    /// Create a new client from a keypair and an already configured pubky client
    ///
    /// Use this to reach a testnet, custom pkarr relays, or non-default timeouts.
    pub fn with_client(keypair: Keypair, client: PubkyHttpClient) -> Self {
        let fetch_config = FetchConfig::default();
        Self {
            transport: PubkyTransport::new(&client, keypair.clone()),
            client,
            session: Mutex::new(None),
            keypair,
            request_permits: request_permits(fetch_config.max_concurrent_requests),
            fetch_config,
        }
    }

    /// Replace the shared concurrency limits, deadlines and retry policy for conversation storage
    pub fn with_fetch_config(mut self, fetch_config: FetchConfig) -> Self {
        self.request_permits = request_permits(fetch_config.max_concurrent_requests);
        self.fetch_config = fetch_config;
        self
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

        Self::new(keypair.into())
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

    fn pubky(&self) -> Pubky {
        Pubky::with_client(self.client.clone())
    }

    fn signer(&self) -> pubky::PubkySigner {
        self.pubky().signer(self.keypair.clone().into())
    }

    /// Sign in to Pubky
    ///
    /// Keeps the session for profile and follow writes. Conversation storage signs in on its
    /// own, scoped to `/pub/private_messages/`, so sending does not require calling this.
    pub async fn sign_in(&self) -> Result<SessionInfo> {
        let session = self.new_session().await?;
        Ok(self.keep(session).await)
    }

    /// A session grant, or the deprecated cookie session from a homeserver that has no grant
    /// endpoint yet, so a client on this release still signs in to an older homeserver
    async fn new_session(&self) -> Result<PubkySession> {
        let signer = self.signer();
        match signer.signin(client_id()).await {
            Ok(session) => Ok(session),
            Err(e) if grant_unsupported(&e) => {
                #[allow(deprecated)]
                let session = signer.signin_cookie().await;
                session.map_err(|e| anyhow!("Failed to sign in: {}", e))
            }
            Err(e) => Err(anyhow!("Failed to sign in: {}", e)),
        }
    }

    async fn keep(&self, session: PubkySession) -> SessionInfo {
        let info = session.info();
        *self.session.lock().await = Some(session);
        info
    }

    /// The kept session, signing in first if there is none
    ///
    /// The lock is held across the sign-in, so concurrent first writes share one session rather
    /// than each minting a grant.
    async fn session(&self) -> Result<PubkySession> {
        let mut kept = self.session.lock().await;
        if let Some(session) = kept.as_ref() {
            return Ok(session.clone());
        }
        let session = self.new_session().await?;
        *kept = Some(session.clone());
        Ok(session)
    }

    /// Create an account on a homeserver and publish it as this identity's homeserver
    ///
    /// # Parameters
    /// - `homeserver`: The homeserver's public key
    /// - `signup_token`: Invite token, if the homeserver requires one
    pub async fn sign_up(
        &self,
        homeserver: &PublicKey,
        signup_token: Option<&str>,
    ) -> Result<SessionInfo> {
        let homeserver = pubky::PublicKey::from(homeserver);
        let signer = self.signer();
        signer
            .signup(&homeserver, signup_token)
            .await
            .map_err(|e| {
                // Transport errors can include the request URL, which may carry the token
                let mut message = e.to_string();
                if let Some(token) = signup_token.filter(|t| !t.is_empty()) {
                    message = message.replace(token, "[redacted]");
                }
                anyhow!("Failed to sign up: {}", message)
            })?;
        // pubky 0.16 separates account creation from the session
        let session = self
            .new_session()
            .await
            .map_err(|e| anyhow!("Signed up, but {}", e))?;
        Ok(self.keep(session).await)
    }

    /// Sign in, creating an account on `homeserver` if this identity has none yet
    ///
    /// Sign-up is only attempted when sign-in fails and no homeserver record can be
    /// resolved for this key. If a record exists, the sign-in error is returned
    /// instead: signing up would republish the record and point the identity away
    /// from the homeserver that holds its data.
    pub async fn ensure_session(
        &self,
        homeserver: &PublicKey,
        signup_token: Option<&str>,
    ) -> Result<SessionInfo> {
        let sign_in_error = match self.sign_in().await {
            Ok(session) => return Ok(session),
            Err(e) => e,
        };

        // A failed lookup is not an absent record, so it must not lead to a sign-up either
        let has_homeserver_record = !matches!(
            self.pubky()
                .get_homeserver_of(&self.keypair.public_key().into())
                .await,
            Ok(None)
        );

        if has_homeserver_record {
            return Err(sign_in_error);
        }

        self.sign_up(homeserver, signup_token).await
    }

    /// Prepare an encrypted message without making network requests.
    ///
    /// Durable callers must persist the returned value before calling [`Self::publish_message`].
    pub fn prepare_message(&self, recipient: &PublicKey, content: &str) -> Result<PreparedMessage> {
        PreparedMessage::prepare(&self.keypair, recipient, content)
    }

    /// Publish the prepared bytes at their stable ID, returning that ID after storage succeeds.
    ///
    /// Repeated publication uses identical bytes and does not create another resource. Stored
    /// does not mean consumed or acknowledged by the peer. A restored value is validated before
    /// any network request. Cancellation leaves the storage outcome unknown; retry the same value.
    pub async fn publish_message(&self, prepared: &PreparedMessage) -> Result<String> {
        publish(
            &self.transport,
            &self.request_permits,
            &self.fetch_config,
            &self.keypair,
            prepared,
        )
        .await
    }

    /// Prepare and publish one encrypted message. Durable callers should use the two steps
    /// separately: calling this convenience method again creates a new message and ID.
    pub async fn send_message(&self, recipient: &PublicKey, content: &str) -> Result<String> {
        self.publish_message(&self.prepare_message(recipient, content)?)
            .await
    }

    /// Cumulative LIST/GET/PUT/DELETE/session attempts, body bytes, retries and admission wait.
    ///
    /// Covers the conversation storage transport. Profile, follow and explicit account
    /// registration operations use the underlying Pubky client and are not included.
    pub fn request_stats(&self) -> RequestStats {
        self.transport.metrics().snapshot()
    }

    /// Get all messages in a conversation, oldest first
    ///
    /// Messages with equal timestamps keep listing order: this client's directory first, then
    /// the other participant's. Fails if any listing or message could not be retrieved under
    /// the [`FetchConfig`] retry policy; use [`Self::fetch_messages`] to keep what was retrieved.
    /// Messages that cannot be parsed or decrypted are skipped.
    pub async fn get_messages(&self, other_pubky: &PublicKey) -> Result<Vec<DecryptedMessage>> {
        let fetch = self.fetch_messages(other_pubky).await?;

        match fetch.failures.first() {
            None => Ok(fetch.messages),
            Some(failure) => Err(anyhow!(
                "Failed to retrieve {} listing(s) or message(s), including {}",
                fetch.failures.len(),
                failure
            )),
        }
    }

    /// Get the messages in a conversation that could be retrieved, and what could not
    ///
    /// Requests run concurrently within this client's [`FetchConfig`] limits.
    pub async fn fetch_messages(&self, other_pubky: &PublicKey) -> Result<MessageFetch> {
        receive_messages(
            &self.transport,
            &self.request_permits,
            &self.fetch_config,
            &self.keypair,
            other_pubky,
        )
        .await
    }

    /// Get the messages in a conversation that `state` has not acknowledged
    ///
    /// Lists both participants' directories, then downloads only the bodies of messages not
    /// acknowledged in `state`. Acknowledge each message with [`ReceiveState::acknowledge`]
    /// once it has been processed. Messages that could not be retrieved are reported in
    /// `failures` and returned again by the next call.
    pub async fn receive_new_messages(
        &self,
        other_pubky: &PublicKey,
        state: &mut ReceiveState,
    ) -> Result<ReceivedMessages> {
        receive_new(
            &self.transport,
            &self.request_permits,
            &self.fetch_config,
            &self.keypair,
            other_pubky,
            state,
        )
        .await
    }

    /// List a conversation and return the messages `state` has not acknowledged, without
    /// downloading them
    ///
    /// Also drops acknowledgements for messages that are no longer listed.
    pub async fn discover_messages(
        &self,
        other_pubky: &PublicKey,
        state: &mut ReceiveState,
    ) -> Result<Discovery> {
        discover(
            &self.transport,
            &self.request_permits,
            &self.fetch_config,
            &self.keypair,
            other_pubky,
            state,
        )
        .await
    }

    /// Download and decrypt messages returned by [`Self::discover_messages`]
    pub async fn retrieve_messages(
        &self,
        other_pubky: &PublicKey,
        pending: &[PendingMessage],
    ) -> Result<ReceivedMessages> {
        retrieve(
            &self.transport,
            &self.request_permits,
            &self.fetch_config,
            &self.keypair,
            other_pubky,
            pending,
        )
        .await
    }

    /// Get the user's own profile
    pub async fn get_own_profile(&self) -> Result<Option<PubkyProfile>> {
        let profile_url = format!(
            "pubky://{}/pub/pubky.app/profile.json",
            self.keypair.public_key()
        );
        let response = self.get(&profile_url).await?;

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
        let response = self.get(&follows_url).await?;

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

        Ok(results.into_iter().flatten().collect())
    }

    /// Get profile for a specific user
    async fn get_user_profile(&self, follow_url: &str) -> Result<FollowedUser> {
        let pubky_id = follow_url
            .split('/')
            .next_back()
            .ok_or_else(|| anyhow!("Failed to extract pubky from URL"))?;

        let profile_url = format!("pubky://{}/pub/pubky.app/profile.json", pubky_id);
        let response = self.get(&profile_url).await?;

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
        let response = self.get(&follows_url).await?;

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

        Ok(results.into_iter().flatten().collect())
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

        let follow_path = format!("/pub/pubky.app/follows/{}", target_pubky);

        self.session()
            .await?
            .storage()
            .put(follow_path, follow_data.to_string())
            .await
            .map_err(|e| anyhow!("Failed to create follow: {}", e))?;

        Ok(())
    }

    /// Unfollow a user by removing them from our follow list
    pub async fn delete_follow(&self, target_pubky: &str) -> Result<()> {
        let follow_path = format!("/pub/pubky.app/follows/{}", target_pubky);

        self.session()
            .await?
            .storage()
            .delete(follow_path)
            .await
            .map_err(|e| anyhow!("Failed to delete follow: {}", e))?;

        Ok(())
    }

    /// Read a public `pubky://` resource, with any HTTP status
    async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let url = url.into_pubky_resource()?.to_transport_url()?;
        let request = self.client.request_async(pubky::Method::GET, url).await?;
        Ok(request.send().await?)
    }

    /// Get the public key of this client
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Get the public key as a string
    pub fn public_key_string(&self) -> String {
        self.keypair.public_key().to_string()
    }

    /// Get the keypair of this client, including its secret key
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Delete a sent message by its ID, succeeding if it is already absent
    ///
    /// Uses the concurrency limits, deadlines and retry policy from [`FetchConfig`].
    pub async fn delete_message(&self, message_id: &str, other_pubky: &PublicKey) -> Result<()> {
        self.delete_messages_with_report(&[message_id.to_string()], other_pubky)
            .await?
            .into_result()
    }

    /// Delete selected sent messages, succeeding if they are already absent
    ///
    /// Every ID is validated before requests begin. All selected messages are attempted even
    /// if another deletion fails. Use [`Self::delete_messages_with_report`] for each outcome.
    pub async fn delete_messages(
        &self,
        message_ids: Vec<String>,
        other_pubky: &PublicKey,
    ) -> Result<()> {
        self.delete_messages_with_report(&message_ids, other_pubky)
            .await?
            .into_result()
    }

    /// Delete selected sent messages and report every outcome
    ///
    /// IDs are the file names returned by [`Self::send_message`], without `.json`. An ID must
    /// be nonempty, consist only of ASCII letters, digits, `-`, `.`, `_` or `~`, and cannot be
    /// `.` or `..`. Invalid input fails before any request. Duplicate IDs are requested once.
    ///
    /// Only this client's files are removed. Requests share the [`FetchConfig`] concurrency
    /// budget with reads, and use its deadlines and retries. A 404 counts as success, so a
    /// persisted cleanup job can safely retry after an interrupted or partially failed call.
    /// The report's `deleted` entries are full message URLs, not IDs.
    pub async fn delete_messages_with_report(
        &self,
        message_ids: &[String],
        other_pubky: &PublicKey,
    ) -> Result<MessageDeletion> {
        delete_messages(
            &self.transport,
            &self.request_permits,
            &self.fetch_config,
            &self.keypair,
            other_pubky,
            message_ids,
        )
        .await
    }

    /// Clear all sent messages in a conversation
    ///
    /// Fails if any listing or deletion fails. Entries outside the sender's conversation
    /// directory are never requested. Use [`Self::clear_messages_with_report`] for each outcome.
    pub async fn clear_messages(&self, other_pubky: &PublicKey) -> Result<()> {
        self.clear_messages_with_report(other_pubky)
            .await?
            .into_result()
    }

    /// Clear the sender's conversation directory and report each deletion or failure
    ///
    /// Lists the full directory before deleting anything. A failed listing leaves all files
    /// untouched. Messages published after listing may remain. This removes every listed
    /// sent message, so prefer [`Self::delete_messages_with_report`] when the conversation
    /// contains multiple active exchanges. The recipient's storage is never modified.
    pub async fn clear_messages_with_report(
        &self,
        other_pubky: &PublicKey,
    ) -> Result<MessageDeletion> {
        clear_messages(
            &self.transport,
            &self.request_permits,
            &self.fetch_config,
            &self.keypair,
            other_pubky,
        )
        .await
    }
}

fn client_id() -> ClientId {
    ClientId::new(CLIENT_ID).expect("a short, nonempty client ID is valid")
}

/// Whether a grant sign-in failed because the homeserver has no grant endpoint, as homeservers
/// before 0.16 do not
fn grant_unsupported(error: &pubky::Error) -> bool {
    matches!(
        error,
        pubky::Error::Request(pubky::errors::RequestError::Server { status, .. })
            if *status == reqwest::StatusCode::NOT_FOUND
                || *status == reqwest::StatusCode::METHOD_NOT_ALLOWED
    )
}
