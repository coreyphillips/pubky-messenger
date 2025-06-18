# Pubky Private Messenger Library - Architecture

## Overview

This library implements end-to-end encrypted private messaging on the Pubky network. Messages are encrypted such that only the sender and recipient can decrypt them, with strong cryptographic guarantees for confidentiality, integrity, and authentication.

## Cryptographic Architecture

### Key Components

1. **Ed25519** - Used for:
   - Keypair generation (signing keys)
   - Message signatures for authentication and integrity

2. **X25519** - Used for:
   - Elliptic Curve Diffie-Hellman (ECDH) key agreement
   - Derived from Ed25519 keys via cryptographic conversion

3. **ChaCha20-Poly1305** - Used for:
   - Authenticated encryption (AEAD) of message content and sender identity
   - Provides both confidentiality and integrity

4. **Blake3** - Used for:
   - Hashing shared secrets to create conversation identifiers
   - Creating message digests for signatures

5. **SHA-512** - Used for:
   - Ed25519 to X25519 key conversion process

## Message Encryption Process

### 1. Shared Secret Generation

The core of the encryption system relies on ECDH shared secrets:

```
shared_secret = sender_x25519_private.diffie_hellman(recipient_x25519_public)
```

This shared secret has a critical property: it's the same whether computed by:
- Sender using their private key + recipient's public key
- Recipient using their private key + sender's public key

### 2. Key Conversion

Since Pubky uses Ed25519 keys for identity, these must be converted to X25519 for encryption:

1. **Private Key Conversion**:
   - Hash Ed25519 private key with SHA-512
   - Clamp the result according to RFC 7748
   - Result is X25519 private key

2. **Public Key Conversion**:
   - Transform Ed25519 curve point to X25519 curve point
   - Uses mathematical curve transformation

### 3. Message Structure

Each encrypted message contains:
- `timestamp`: Unix timestamp with nanosecond precision
- `encrypted_sender`: Sender's public key encrypted with shared secret
- `encrypted_content`: Message content encrypted with shared secret
- `signature`: Ed25519 signature over (content + sender_pubkey + timestamp)

### 4. Encryption Flow

1. Generate shared secret using ECDH
2. Create message digest: `Blake3(content || sender_pubkey || timestamp)`
3. Sign the digest with sender's Ed25519 private key
4. Encrypt content using ChaCha20-Poly1305 with shared secret
5. Encrypt sender identity using ChaCha20-Poly1305 with shared secret
6. Package into PrivateMessage structure

## Message Storage

Messages are stored on the Pubky network at deterministic paths:

```
/pub/private_messages/{conversation_id}/{message_id}.json
```

Where:
- `conversation_id` = Blake3 hash of the shared secret
- `message_id` = Randomly generated UUID v4

This ensures:
- Both parties can find messages without coordination
- Messages remain encrypted at rest on the network
- No metadata leakage about conversation participants

## Message Decryption Process

### 1. Conversation Discovery

Clients check both potential message locations:
- Sender's path: `pubky://{sender}/pub/private_messages/{conversation_id}/`
- Recipient's path: `pubky://{recipient}/pub/private_messages/{conversation_id}/`

### 2. Decryption Flow

1. Retrieve encrypted message from Pubky network
2. Generate shared secret using recipient's private key + sender's public key
3. Decrypt sender identity to determine actual sender
4. Decrypt message content
5. Verify Ed25519 signature using decrypted sender's public key
6. Return decrypted message with verification status

## Security Properties

### Achieved Properties

1. **Confidentiality**: Only sender and recipient can decrypt messages
2. **Authentication**: Ed25519 signatures verify sender identity
3. **Integrity**: AEAD encryption and signatures ensure message hasn't been tampered
4. **Non-repudiation**: Signatures cryptographically prove sender created the message

### Limitations

1. **No Forward Secrecy**: Uses static keypairs, so key compromise reveals all messages
2. **No Post-Compromise Security**: Compromised keys allow decryption of future messages
3. **Metadata**: Message existence and timestamps are visible on the network

## Implementation Details

### Core Modules

- `src/crypto.rs`: Key conversion and shared secret generation
- `src/message.rs`: Message encryption/decryption and structure definitions
- `src/client.rs`: High-level client API for sending/receiving messages

### Dependencies

- `pubky`: Core Pubky functionality and key management
- `pubky_common::crypto`: ChaCha20-Poly1305 encryption
- `ed25519-dalek`: Ed25519 signatures
- `x25519-dalek`: X25519 key agreement
- `blake3`: Hashing

## Usage Example

```rust
// Create client
let client = PrivateMessengerClient::new(keypair);

// Send message
let encrypted_msg = client.send_message(recipient_pubkey, "Hello, world!").await?;

// Receive messages
let messages = client.get_messages(sender_pubkey).await?;
for msg in messages {
    println!("From: {}", msg.sender);
    println!("Content: {}", msg.content);
    println!("Verified: {}", msg.verified);
}
```

## Future Considerations

1. **Forward Secrecy**: Implement ephemeral key rotation (e.g., Double Ratchet)
2. **Group Messaging**: Extend to support multi-party conversations
3. **Message Deletion**: Add secure deletion capabilities
4. **Rich Media**: Support for encrypted attachments and media