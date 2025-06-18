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
pubky-messenger = "0.1.0"
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
    
    // Create client
    let client = PrivateMessengerClient::from_recovery_file(&recovery_file, "your_passphrase")?;
    
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

## API Reference

### `PrivateMessengerClient`

The main client for interacting with the Pubky messaging system.

#### Methods

- `new(keypair: Keypair) -> Result<Self>` - Create a new client from a keypair
- `from_recovery_file(bytes: &[u8], passphrase: &str) -> Result<Self>` - Create from recovery file
- `sign_in(&self) -> Result<Session>` - Sign in to the homeserver
- `send_message(&self, recipient: &PublicKey, content: &str) -> Result<String>` - Send encrypted message
- `get_messages(&self, other: &PublicKey) -> Result<Vec<DecryptedMessage>>` - Get conversation messages
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

## Security

This library implements end-to-end encryption using:
- X25519-ECDH for key agreement
- ChaCha20-Poly1305 for message encryption (via pubky-common)
- Ed25519 for message signatures
- Blake3 for hashing

Messages are encrypted with a shared secret derived from the sender and recipient's keypairs.

## License

MIT