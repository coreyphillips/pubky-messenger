# Pubky Messenger

A Rust library for secure private messaging using the Pubky protocol. This library provides end-to-end encrypted messaging capabilities with authentication via pkarr recovery files.

## Features

- 🔐 End-to-end encrypted messaging using X25519-ECDH
- 🔑 Authentication via pkarr recovery files
- ✅ Message signature verification using Ed25519
- 👥 Profile and contact management
- 🔄 Async/await API using Tokio

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
pubky-messenger = "0.4.0"
```

## Usage

### Basic Example

```rust
use pubky_messenger::{PrivateMessengerClient, PublicKey};
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Load recovery file
    let recovery_file = std::fs::read("recovery.pkarr")?;

    // Create client with passphrase
    let client = PrivateMessengerClient::from_recovery_file(&recovery_file, Some("your_passphrase"))?;

    // Or without passphrase (defaults to empty string)
    // let client = PrivateMessengerClient::from_recovery_file(&recovery_file, None)?;

    // Sign in
    client.sign_in().await?;

    // Send a message
    let recipient = PublicKey::try_from("recipient_public_key_here")?;
    let message_id = client.send_message(&recipient, "Hello, world!").await?;
    println!("Message sent with ID: {}", message_id);

    // Get messages
    let messages = client.get_messages(&recipient).await?;
    for msg in messages {
        println!("{}: {}", msg.sender, msg.content);
    }

    Ok(())
}
```

### Creating a Client from Keypair

If you already have a keypair, you can create the client directly:

```rust
use pkarr::Keypair;
use pubky_messenger::PrivateMessengerClient;

let keypair = Keypair::random();
let client = PrivateMessengerClient::new(keypair)?;
```

### Durable Sending

Prepare an encrypted message before making network requests:

```rust
let prepared = client.prepare_message(&recipient, "request content")?;
let saved = serde_json::to_vec(&prepared)?;
```

Save `saved` with the application's durable outbox transaction before publishing. After a
restart, deserialize it into `PreparedMessage` and publish the same value:

```rust
use pubky_messenger::PreparedMessage;

let prepared: PreparedMessage = serde_json::from_slice(&saved)?;
let id = client.publish_message(&prepared).await?;
```

Every attempt sends the same encrypted bytes to the same ID. If a homeserver stores the
message but its response is lost, retrying does not create a second message. The prepared
format is versioned and signs the owner, recipient, ID and encrypted payload together.
Restored values are validated before I/O. The destination is derived locally, never loaded
as an arbitrary URL. `prepared.id()` also identifies the exact resource for later cleanup.

`send_message` remains a prepare-and-publish convenience wrapper. Calling it again creates
a fresh message. Durable callers must retain a prepared value when publication fails or is
cancelled. The library owns neither an outbox database nor a background retry worker.
Successful publication means stored, not consumed or acknowledged by the recipient. An
application request ID in the content remains separate from the transport resource ID.

### Request Limits and Metrics

`FetchConfig` governs conversation reads, prepared publication and deletion. Attempts share
a client budget, acquire per-call permits, release them during backoff, and stop at the
configured deadline. Cleanup is additionally limited to half the client budget, rounded
down with a minimum of one, so a cleanup backlog leaves foreground capacity when the client
has at least two slots. With one slot, FIFO admission and attempt deadlines bound each turn.

The deadline covers one admitted attempt, including any session establishment or refresh.
It does not cover queue wait, retry backoff or an entire multi-page operation. Wrap the
whole operation in `tokio::time::timeout` when it has an application deadline. Cancellation
releases capacity, but the outcome of an interrupted PUT or DELETE is unknown. Retain the
prepared message or cleanup IDs and retry them.

Authenticated mutations establish a scoped session as needed. Concurrent requests with an
expired session share a refresh. Each attempt refreshes at most once and repeats the
mutation at most once. Persistent authentication rejection is reported as
`FailureReason::Authentication(status)`; transient sign-in failures follow the configured
retry policy. Publication errors can be downcast to `FetchFailure` for classification.

`client.request_stats()` returns cumulative LIST, GET, PUT, DELETE and session attempt counts,
body bytes, retries, timeouts and admission wait. It records no payloads, destinations or
credentials. Body bytes count bytes offered for upload and complete response bodies read,
including retries and errors. They exclude headers and TLS; interrupted transfers may move
different amounts on the wire. Explicit account, profile and follow operations are outside
these counters. Compare snapshots around a workload to measure actual storage requests.

### Creating a Client from Recovery Phrase

You can also create a client using a 12-word mnemonic recovery phrase with optional passphrase and language:

```rust
use pubky_messenger::PrivateMessengerClient;

// Basic usage - defaults to English, no passphrase
let mnemonic = "your twelve word recovery phrase goes here with spaces between words";
let client = PrivateMessengerClient::from_recovery_phrase(mnemonic, None, None)?;

// Sign in and use as normal
client.sign_in().await?;
```

**With optional passphrase for additional security:**

```rust
// Add a passphrase for extra security
let client_with_passphrase = PrivateMessengerClient::from_recovery_phrase(
    mnemonic,
    Some("my_secure_passphrase"),  // Optional passphrase
    None,                           // Use default English
)?;
```

**With different language:**

```rust
use pubky_messenger::{Language, PrivateMessengerClient};

// Use a different language
let client = PrivateMessengerClient::from_recovery_phrase(
    mnemonic,
    None,                           // No passphrase
    Some(Language::English),        // Explicit language
)?;
```

**With both passphrase and language:**

```rust
let client = PrivateMessengerClient::from_recovery_phrase(
    mnemonic,
    Some("my_passphrase"),          // Optional passphrase
    Some(Language::English),        // Optional language
)?;
```

The recovery phrase must be:
- Exactly 12 words from the BIP39 wordlist for the specified language
- In the correct format for that language (e.g., lowercase for English)
- Separated by single spaces

**Parameters:**
- `mnemonic_phrase`: The 12-word BIP39 mnemonic (required)
- `passphrase`: Optional passphrase for additional security (defaults to empty string)
- `language`: Optional language for mnemonic validation (defaults to English)

This method provides a deterministic way to recover your keypair from a mnemonic phrase. The same mnemonic with the same passphrase and language will always produce the same keypair.

### Creating an Account

A new identity has no homeserver account, so `sign_in` fails until it signs up. `ensure_session` signs in, and signs up on the given homeserver only when the identity has no homeserver record yet:

```rust
use pubky_messenger::{PrivateMessengerClient, PublicKey};

let homeserver = PublicKey::try_from("homeserver_public_key")?;
let client = PrivateMessengerClient::from_recovery_phrase(mnemonic, None, None)?;

// Optional signup token, if the homeserver requires one
client.ensure_session(&homeserver, None).await?;
```

To use a testnet, custom pkarr relays, or other client settings, build the pubky client yourself:

```rust
use pubky_messenger::{pubky, Keypair, PrivateMessengerClient};

let pubky_client = pubky::Client::builder().testnet().build()?;
let client = PrivateMessengerClient::with_client(Keypair::random(), pubky_client);
```

### Working with Profiles

```rust
// Get your own profile
if let Some(profile) = client.get_own_profile().await? {
    println!("Name: {}", profile.name);
    println!("Bio: {:?}", profile.bio);
}

// Get followed users
let followed = client.get_followed_users().await?;
for user in followed {
    println!("{}: {}", user.pubky, user.name.unwrap_or_default());
}
```

### Reading Messages

`get_messages` returns a conversation oldest first, and fails rather than returning a partial
history if any listing or message could not be retrieved. `fetch_messages` returns what was
retrieved together with the failures.

Requests run concurrently, bounded per conversation and across the whole client, with a
deadline and retries for timeouts, transport errors, 429 and 5xx responses. See `FetchConfig`
for the defaults and the exact retry policy. Listings are read page by page until the homeserver
returns an empty page, so conversations longer than one page are read in full.

```rust
use pubky_messenger::FetchConfig;
use std::time::Duration;

let client = client.with_fetch_config(FetchConfig {
    max_concurrent_requests: 8,
    max_concurrent_requests_per_conversation: 4,
    request_timeout: Duration::from_secs(5),
    ..FetchConfig::default()
});

let fetch = client.fetch_messages(&recipient).await?;
for failure in &fetch.failures {
    eprintln!("not retrieved: {}", failure);
}
```

### Receiving New Messages

`get_messages` downloads and decrypts every message on each call. To poll a conversation,
keep a `ReceiveState` and call `receive_new_messages`. It lists both participants' directories
and downloads only messages the state has not acknowledged, so polling an unchanged
conversation costs listing requests and nothing else.

```rust
use pubky_messenger::ReceiveState;

// Restore a saved state, or start from ReceiveState::default() on the first run
let mut state: ReceiveState = match std::fs::read("state.json") {
    Ok(saved) => serde_json::from_slice(&saved)?,
    Err(_) => ReceiveState::default(),
};

let received = client.receive_new_messages(&recipient, &mut state).await?;
for item in &received.messages {
    if let Some(message) = &item.message {
        println!("{}: {}", message.sender, message.content);
    }
    // Acknowledge after processing, including bodies that could not be decrypted
    state.acknowledge(item);
}
std::fs::write("state.json", serde_json::to_vec(&state)?)?;
```

- Delivery is at least once. A message is returned again until it is acknowledged, so
  failed downloads and crashes before saving the state are retried. `MessageId` (publisher
  and URL) identifies a message across calls.
- Discovery and retrieval can run separately: `discover_messages` lists `PendingMessage`s, each
  with its `MessageId`, in `Discovery::pending` without downloading anything.
  `retrieve_messages` downloads the `PendingMessage`s you pass it.
- Listings are read in full on every call. Message names are random UUIDs, so a new message
  can sort anywhere in a listing and there is no position to resume from.
- The state keeps one entry per acknowledged message that is still listed. Entries for
  deleted messages are dropped at the next complete listing.
- `ChangePolicy::WriteOnce`, the default, never requests an acknowledged message again, so a
  message rewritten in place is not seen. This library never rewrites messages.
  `ChangePolicy::Revalidate` sends a conditional request for every acknowledged message on
  each call. Unchanged messages cost a request but no body, and changed ones are delivered
  again with `updated` set.

### Managing Messages

The library provides methods to delete messages from your conversations:

```rust
// Delete a single message
let message_id = "550e8400-e29b-41d4-a716-446655440000";
client.delete_message(message_id, &recipient).await?;

// Delete multiple messages at once
let message_ids = vec![
    "id1".to_string(),
    "id2".to_string(),
    "id3".to_string(),
];
client.delete_messages(message_ids, &recipient).await?;

// Clear all your sent messages in a conversation
client.clear_messages(&recipient).await?;
```

**Note:** These delete operations only remove messages from your own storage on the Pubky network. Messages stored by the recipient remain unchanged.

Deletions use the same `FetchConfig` concurrency budget, attempt deadline and retry policy as
reads. An already absent message (404) counts as success. Duplicate IDs are deleted once,
and every supplied ID is validated before any request begins.

For durable cleanup jobs, retain the IDs returned by `send_message` and delete only the
messages belonging to the completed exchange. Clearing a whole conversation also removes
messages for any other active exchange with that peer. Both participants must clean up their
own sent messages, after the application has safely recorded the outcome and no longer needs
the messages for recovery.

Use the report methods to inspect partial failures without losing successful outcomes:

```rust
let report = client.delete_messages_with_report(&message_ids, &recipient).await?;
for failure in &report.failures {
    eprintln!("cleanup pending: {}", failure);
}
// report.deleted contains full URLs successfully removed or already absent.
// Retrying the same IDs is safe, including after a crash or timeout.
```

`clear_messages_with_report` provides the same report for a complete conversation listing.
It deletes nothing if listing fails, and reports entries outside the sender's conversation
without requesting them. Messages published after listing may remain. The existing
`delete_message`, `delete_messages` and `clear_messages` methods return an error if any
operation fails, after attempting all valid selected messages.

## API Reference

### `PrivateMessengerClient`

The main client for interacting with the Pubky messaging system.

#### Methods

- `new(keypair: Keypair) -> Result<Self>` - Create a new client from a keypair
- `with_client(keypair: Keypair, client: pubky::Client) -> Self` - Create a client using an already configured pubky client
- `from_recovery_file(bytes: &[u8], passphrase: Option<&str>) -> Result<Self>` - Create from recovery file with optional passphrase
- `from_recovery_phrase(mnemonic: &str, passphrase: Option<&str>, language: Option<Language>) -> Result<Self>` - Create from 12-word BIP39 mnemonic with optional passphrase and language
- `sign_in(&self) -> Result<Session>` - Sign in to the homeserver
- `sign_up(&self, homeserver: &PublicKey, signup_token: Option<&str>) -> Result<Session>` - Create an account on a homeserver
- `ensure_session(&self, homeserver: &PublicKey, signup_token: Option<&str>) -> Result<Session>` - Sign in, signing up first if the identity has no homeserver yet
- `send_message(&self, recipient: &PublicKey, content: &str) -> Result<String>` - Send encrypted message
- `prepare_message(&self, recipient: &PublicKey, content: &str) -> Result<PreparedMessage>` - Prepare a stable encrypted publication before I/O
- `publish_message(&self, prepared: &PreparedMessage) -> Result<String>` - Publish or retry the prepared ID and exact payload
- `request_stats(&self) -> RequestStats` - Snapshot cumulative storage request and body-byte counters
- `with_fetch_config(self, config: FetchConfig) -> Self` - Set shared concurrency limits, deadlines and retries for reads, publication and cleanup
- `get_messages(&self, other: &PublicKey) -> Result<Vec<DecryptedMessage>>` - Get conversation messages, failing if any could not be retrieved
- `fetch_messages(&self, other: &PublicKey) -> Result<MessageFetch>` - Get the conversation messages that could be retrieved, and what could not
- `receive_new_messages(&self, other: &PublicKey, state: &mut ReceiveState) -> Result<ReceivedMessages>` - Get the messages `state` has not acknowledged
- `discover_messages(&self, other: &PublicKey, state: &mut ReceiveState) -> Result<Discovery>` - List the messages `state` has not acknowledged, without downloading them
- `retrieve_messages(&self, other: &PublicKey, pending: &[PendingMessage]) -> Result<ReceivedMessages>` - Download and decrypt discovered messages
- `delete_message(&self, message_id: &str, other: &PublicKey) -> Result<()>` - Delete a single message
- `delete_messages(&self, message_ids: Vec<String>, other: &PublicKey) -> Result<()>` - Delete multiple messages
- `delete_messages_with_report(&self, message_ids: &[String], other: &PublicKey) -> Result<MessageDeletion>` - Delete selected messages and report successful URLs and failures
- `clear_messages(&self, other: &PublicKey) -> Result<()>` - Clear all sent messages in a conversation
- `clear_messages_with_report(&self, other: &PublicKey) -> Result<MessageDeletion>` - Clear sent messages and report successful URLs and failures
- `get_own_profile(&self) -> Result<Option<PubkyProfile>>` - Get user's profile
- `get_followed_users(&self) -> Result<Vec<FollowedUser>>` - Get followed users
- `public_key(&self) -> PublicKey` - Get the client's public key
- `public_key_string(&self) -> String` - Get public key as string
- `keypair(&self) -> &Keypair` - Get the client's keypair, including the secret key

### Types

- `DecryptedMessage` - A decrypted message with sender, content, timestamp, and verification status
- `FetchConfig` - Concurrency limits, request deadline and retry policy for reading and deleting messages
- `MessageFetch` - Retrieved messages and a `FetchFailure` for each listing or message that could not be retrieved
- `MessageDeletion` - Successfully deleted or already absent message URLs and a `FetchFailure` for each failed listing or deletion
- `PreparedMessage` - Versioned, serializable and authenticated publication intent with a stable ID and exact encrypted payload
- `RequestStats` - Per-method attempts and body bytes, retry and timeout counts, and aggregate admission wait
- `ReceiveState` - Serializable record of acknowledged messages in one conversation, with its `ChangePolicy`
- `ReceivedMessage` - A retrieved message with its `MessageId`, entity tag, and whether it changed since it was acknowledged
- `PubkyProfile` - User profile information (name, bio, image, status)
- `FollowedUser` - Information about a followed user

### Error Handling

All methods return `Result<T>` where the error type is `anyhow::Error`. This provides flexible error handling with context. Common error scenarios include:
- Network connectivity issues
- Invalid recovery file or passphrase
- Encryption/decryption failures
- Missing or invalid public keys

Example error handling:
```rust
match client.send_message(&recipient, "Hello").await {
    Ok(message_id) => println!("Message sent: {}", message_id),
    Err(e) => eprintln!("Failed to send message: {}", e),
}
```

## Examples

Check the `examples/` directory for more detailed examples:

### Basic Usage Example

```bash
# Run the basic usage example
cargo run --example basic_usage -- path/to/recovery.pkarr [optional_recipient_pubky]
```

This example demonstrates:
- Loading a recovery file and signing in
- Displaying your profile information
- Listing followed users
- Sending a test message (if recipient pubky provided)
- Reading conversation messages

### Send Message Example

```bash
# Send a message to a specific pubky
cargo run --example send_message -- path/to/recovery.pkarr recipient_pubky "Your message here"

# Example:
cargo run --example send_message -- recovery.pkarr pk:q9x5sfjbpajdebk45b9jashgb86iem7rnwpmu16px3ens63xzwro "Hello there!"
```

This example:
- Takes a recovery file, recipient pubky, and message as arguments
- Signs in to Pubky
- Sends the message to the specified recipient
- Displays the message ID and timestamp

### Read Messages Example

```bash
# Read all messages from a conversation with a specific pubky
cargo run --example read_messages -- path/to/recovery.pkarr peer_pubky

# Example:
cargo run --example read_messages -- recovery.pkarr pk:q9x5sfjbpajdebk45b9jashgb86iem7rnwpmu16px3ens63xzwro
```

This example:
- Takes a recovery file and peer pubky as arguments
- Signs in to Pubky
- Fetches all messages from the conversation
- Displays messages in a formatted, chronological order
- Shows sender information, timestamps, and verification status

### Real-time Conversation Example

```bash
# Start an interactive chat session with a specific pubky
cargo run --example conversation -- path/to/recovery.pkarr peer_pubky

# Example:
cargo run --example conversation -- recovery.pkarr pk:q9x5sfjbpajdebk45b9jashgb86iem7rnwpmu16px3ens63xzwro
```

This example provides a real-time chat experience:
- Shows the last 10 messages when starting
- Allows you to type and send messages interactively
- Automatically checks for new messages every 3 seconds, downloading only new ones
- Displays messages with timestamps in HH:MM:SS format
- Press Ctrl+C to exit the chat session

**Features:**
- Real-time message polling
- Interactive terminal UI
- Message history display
- Automatic new message detection
- Clean, chat-like interface

## Testing

### Running Tests

The library includes comprehensive unit and integration tests. Due to API rate limiting, it's recommended to run tests sequentially:

```bash
# Run all tests sequentially (recommended)
cargo test -- --test-threads=1

# Run specific test file
cargo test --test test_delete_methods -- --test-threads=1

# Run with output for debugging
cargo test -- --test-threads=1 --nocapture

# Compare receive time under injected latency, and key derivation CPU cost
cargo test --lib receive_latency_report -- --ignored --nocapture
cargo test --release --lib key_derivation_report -- --ignored --nocapture
```

### Test Files with Recovery Keys

The repository includes test recovery files (`p1.pkarr` and `p2.pkarr`) in the root directory for integration testing. Both use `"password"` as the passphrase.

**Important:** These test files are for development only and should never be used in production.

### Writing Tests

When writing tests that interact with the Pubky network:
1. Use unique message content with timestamps to avoid conflicts
2. Add delays between operations when necessary (`tokio::time::sleep`)
3. Handle existing messages in conversations gracefully
4. Run tests sequentially to avoid rate limiting

## Security

This library implements end-to-end encryption using:
- X25519-ECDH for key agreement
- XSalsa20-Poly1305 for message encryption, with a random 24-byte nonce prepended to each ciphertext (via pubky-common)
- Ed25519 for message signatures
- Blake3 for hashing

Messages are encrypted with a shared secret derived from the sender and recipient's keypairs.

## License

MIT
