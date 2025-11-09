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
pubky-messenger = "0.2.1"
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

## API Reference

### `PrivateMessengerClient`

The main client for interacting with the Pubky messaging system.

#### Methods

- `new(keypair: Keypair) -> Result<Self>` - Create a new client from a keypair
- `from_recovery_file(bytes: &[u8], passphrase: Option<&str>) -> Result<Self>` - Create from recovery file with optional passphrase
- `from_recovery_phrase(mnemonic: &str, passphrase: Option<&str>, language: Option<Language>) -> Result<Self>` - Create from 12-word BIP39 mnemonic with optional passphrase and language
- `sign_in(&self) -> Result<Session>` - Sign in to the homeserver
- `send_message(&self, recipient: &PublicKey, content: &str) -> Result<String>` - Send encrypted message
- `get_messages(&self, other: &PublicKey) -> Result<Vec<DecryptedMessage>>` - Get conversation messages
- `delete_message(&self, message_id: &str, other: &PublicKey) -> Result<()>` - Delete a single message
- `delete_messages(&self, message_ids: Vec<String>, other: &PublicKey) -> Result<()>` - Delete multiple messages
- `clear_messages(&self, other: &PublicKey) -> Result<()>` - Clear all sent messages in a conversation
- `get_own_profile(&self) -> Result<Option<PubkyProfile>>` - Get user's profile
- `get_followed_users(&self) -> Result<Vec<FollowedUser>>` - Get followed users
- `public_key(&self) -> PublicKey` - Get the client's public key
- `public_key_string(&self) -> String` - Get public key as string

### Types

- `DecryptedMessage` - A decrypted message with sender, content, timestamp, and verification status
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
- Automatically checks for new messages every 3 seconds
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
- ChaCha20-Poly1305 for message encryption (via pubky-common)
- Ed25519 for message signatures
- Blake3 for hashing

Messages are encrypted with a shared secret derived from the sender and recipient's keypairs.

## License

MIT