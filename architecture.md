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

3. **XSalsa20-Poly1305** - Used for:
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
- `timestamp`: Unix timestamp in seconds, stored in plaintext
- `encrypted_sender`: Sender's public key as its 52-character z-base-32 string, encrypted with shared secret
- `encrypted_content`: Message content (UTF-8) encrypted with shared secret
- `signature_bytes`: 64-byte Ed25519 signature over the message digest (see Encryption Flow)

Stored JSON uses these field names, with each byte field serialized as an array of integers.

`encrypted_sender` and `encrypted_content` are each the output of `pubky_common::crypto::encrypt`, keyed with the 32-byte shared secret:

```
nonce (24 bytes, random per field) || Poly1305 tag (16 bytes) || ciphertext
```

An empty plaintext encrypts to an empty byte string, with no nonce or tag.

### 4. Encryption Flow

1. Generate shared secret using ECDH
2. Create message digest: `Blake3(content || sender_pubky || timestamp)`, where `content` is the UTF-8 bytes, `sender_pubky` is the raw 32-byte Ed25519 public key, and `timestamp` is a big-endian u64
3. Sign the digest with sender's Ed25519 private key
4. Encrypt content using XSalsa20-Poly1305 with shared secret
5. Encrypt sender identity using XSalsa20-Poly1305 with shared secret
6. Package into PrivateMessage structure

## Message Storage

Messages are stored on the Pubky network at deterministic paths:

```
/pub/private_messages/{conversation_id}/{message_id}.json
```

Where:
- `conversation_id` = Blake3 hash of the lowercase hex encoding of the 32-byte shared secret (the 64 ASCII characters, not the raw bytes), written as lowercase hex
- `message_id` = Randomly generated UUID v4

This ensures:
- Both parties can find messages without coordination
- Messages remain encrypted at rest on the network
- Conversation paths do not contain the participants' keys, although publisher identity,
  message existence and request patterns remain visible to the storage service

## Publication and Recovery

`PreparedMessage` separates encryption from network I/O. Version 1 stores a canonical UUID,
owner, recipient, exact serialized `PrivateMessage` bytes and a signature binding these fields.
The binding hashes the domain string `pubky-messenger/prepared-message`, the one-byte version,
then ID, owner, recipient and payload as length-prefixed byte strings. Lengths are big-endian
u64 values. The owner signs that Blake3 digest with its Ed25519 key. This prepared envelope
belongs in the application's durable outbox. Only its unchanged encrypted payload is published,
so the wire message format and conversation path remain compatible with earlier messages.

Publication validates the envelope, reconstructs the destination from the local identity and
recipient, and sends a PUT with the same resource ID and bytes on every attempt. A lost response
or process restart can cause a repeated PUT but cannot create another resource when the same
prepared value is retried. Successful storage is not evidence of peer consumption. Application
request IDs, outbox persistence, inbox processing and protocol acknowledgments belong to the
caller.

The request engine shares concurrency and retries across reads, publication and cleanup.
Cleanup has a separate admission limit of half the client slots, with a minimum of one.
This keeps capacity available for foreground work when multiple slots are configured.
Attempt deadlines include session establishment and one coordinated refresh after expiry;
queue wait and backoff require a caller-owned total deadline. Persistent authentication
failure remains a typed failure. Cancellation releases permits and leaves ambiguous mutation
outcomes retryable through their saved prepared value or selected cleanup IDs.

Directory discovery still scans both participant listings in full because UUID names are not
chronological cursors. `ReceiveState` suppresses acknowledged body downloads, with at-least-once
delivery until the caller processes and persists its acknowledgment. Targeted cleanup removes
only the caller's selected resources. Whole-conversation clearing is inappropriate when another
active exchange with the peer still needs its messages.

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
- `src/prepared.rs`: Validated durable publication intent and stable retries
- `src/receive.rs`: Shared admission, transport requests, authentication and retry policy
- `src/incremental.rs`: Discovery, retrieval and serializable acknowledgment state
- `src/clear.rs`: Selected cleanup and per-resource outcomes
- `src/metrics.rs`: Request and body-byte counters without message contents

### Dependencies

- `pubky`: Core Pubky functionality and key management
- `pubky_common::crypto`: XSalsa20-Poly1305 encryption
- `ed25519-dalek`: Ed25519 signatures
- `x25519-dalek`: X25519 key agreement
- `blake3`: Hashing

## Usage Example

```rust
// Create client
let client = PrivateMessengerClient::new(keypair);

// Send message
let encrypted_msg = client.send_message(recipient_pubky, "Hello, world!").await?;

// Receive messages
let messages = client.get_messages(sender_pubky).await?;
for msg in messages {
    println!("From: {}", msg.sender);
    println!("Content: {}", msg.content);
    println!("Verified: {}", msg.verified);
}
```

## Future Considerations

1. **Forward Secrecy**: Implement ephemeral key rotation (e.g., Double Ratchet)
2. **Group Messaging**: Extend to support multi-party conversations
3. **Retention Policy**: Applications coordinate recovery-safe cleanup; remote deletion does not erase recipient copies or storage backups
4. **Rich Media**: Support for encrypted attachments and media
