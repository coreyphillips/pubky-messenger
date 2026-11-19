# pubky-messenger protocol v2: messaging keys

Status: draft, implemented first in pubky-messenger-ts.

## Why v2

Protocol v1 derives every conversation key from the two participants' Ed25519 identity secrets.
Apps that sign in through Pubky Ring grants never see the identity secret, so they cannot use v1.
Pubky grants can deliver scoped content keys (the `e` capability action) that the signer derives
deterministically from the identity secret. v2 derives a separate messaging keypair from such a
key and publishes its public half, so a grant-based app can message without the identity secret,
and every device approved for the same scope derives the same messaging key.

Everything not stated here is unchanged from v1 (`architecture.md` of the Rust crate): the
ed25519 to x25519 conversion, X25519 with small-order rejection, XSalsa20-Poly1305 via the
pubky-common layout `nonce(24) || tag(16) || ciphertext`, empty plaintext encoding to an empty
byte string, Blake3, UUID v4 message names, Unix-second timestamps, byte fields serialized as JSON
arrays of integers, and compact JSON with keys in the order shown.

## 1. Messaging seed

```
MESSAGING_KEY_PATH = "/priv/private_messages/v2/messaging-key"
seed = pubky hierarchical keys v1 file-content key for MESSAGING_KEY_PATH
```

An app obtains `seed` from a signed grant approval (`approvalFormat: "signedApprovalV1"`) that
includes the capability `/priv/private_messages/v2/messaging-key:e` (or an `e` capability on any
ancestor directory), via `EncryptionKeys.deriveForPath(MESSAGING_KEY_PATH)`.

A holder of the identity secret derives the same value locally, following pubky-common 0.17.1
`encryption_keys.rs` (derivation version `v1`):

```
root = HKDF-SHA-256(ikm = identity_secret, salt = none, info = "pubky/hierarchical-keys/v1/root", L = 32)
for each directory segment s of the path (here "priv", "private_messages", "v2"):
    k = HKDF-Expand-SHA-256(prk = k_parent, info = "pubky/hierarchical-keys/v1/directory" || 0x00 || utf8(s), L = 32)
seed = HKDF-Expand-SHA-256(prk = k_last_dir, info = "pubky/hierarchical-keys/v1/file-content" || 0x00 || utf8("messaging-key"), L = 32)
```

`k_parent` of the first segment is `root`. Implementations must check the segment handling against
the pubky-common source and the vectors below.

Vectors (identity secret, then seed):

| identity secret | seed |
|---|---|
| `11` x 32 | `1b217aeb88b26eafca4805fbca7195036b70a5163641df2716e3c681c0cbf569` |
| `22` x 32 | `313083956f1fdeaa0b872a814d9f5051819796f5a9629fcd3286f63b49c31f9c` |
| secret of `p1.pkarr` (passphrase `password`) | `34d4621ddc5bc6479b99a908ca624bebf876d9b753d0688b3a9af371f9ac9f8a` |

## 2. Messaging keypair

The messaging keypair is the Ed25519 keypair whose 32-byte secret key is `seed`. Its public key is
written `M` (32 bytes, z-base-32 when encoded as text). The identity public key is written `I`.

## 3. Key record

Each participant publishes, on their own homeserver:

```
pubky://<I_z32>/pub/private_messages/v2/key.json
{"version":2,"owner":"<I_z32>","messaging_key":"<M_z32>","created_at":<u64 microseconds>,"signature":[<64 ints>]}
```

```
key_digest = blake3("pubky-messenger/v2/key-record" || I_raw32 || M_raw32)
signature  = Ed25519-Sign(seed, key_digest)
```

A reader fetching the record for identity `I` requires: `version == 2`, `owner == I`,
`messaging_key` decodes to a valid Ed25519 point whose X25519 conversion succeeds and that is not
of small order (an all-zero shared secret, see section 4), and `signature` verifies under `M`.
`owner` and `messaging_key` are bare 52-character z-base-32 keys; readers ignore unknown fields.
A 404 means the identity has not enabled v2 messaging. Any other failure means the record is
invalid; it is not treated as absent.

The record is bound to the identity by homeserver write authority: only a session authorized by
`I` can write under `I`'s `/pub/`. The signature proves possession of `M`; it does not replace that
binding. Republishing is idempotent apart from `created_at`.

## 4. Conversation key and path

```
shared = X25519(x25519_secret(seed_self), x25519_public(M_peer))   // all-zero output is rejected
cid    = lowercase_hex(blake3(lowercase_hex(shared)))
dir    = "/pub/private_messages/v2/" || cid || "/"
```

The v2 directory never collides with v1 conversation directories, which sit directly under
`/pub/private_messages/` and are named by 64 hex characters.

## 5. Message

Stored at `pubky://<sender I_z32><dir><uuid>.json`, always on the sender's own homeserver:

```
{"version":2,"timestamp":<u64 seconds>,"encrypted_sender":[..],"encrypted_content":[..],"signature_bytes":[<64 ints>]}
```

```
encrypted_sender  = secretbox(shared, utf8(sender_I_z32))
encrypted_content = secretbox(shared, utf8(content))
digest            = blake3("pubky-messenger/v2/message" || utf8(content) || sender_I_raw32 || recipient_I_raw32 || u64_be(timestamp))
signature_bytes   = Ed25519-Sign(sender_seed, digest)
```

The trailing 72 bytes of the digest input have a fixed length, so the variable-length content is
unambiguous. Binding the recipient prevents a participant from re-wrapping a signed message into a
different conversation.

A reader in the conversation between `me` and `peer`:

1. Lists `pubky://<me><dir>` and `pubky://<peer><dir>` with the same pagination and strict entry
   filter as v1, and fetches each entry.
2. Rejects bodies whose `version` is not 2. Such bodies, like malformed or undecryptable ones,
   are not messages: a full read skips them, and incremental receive returns them without a
   message so they can be acknowledged.
3. Decrypts `encrypted_sender` and requires it to equal the owner of the directory the entry was
   listed from. A mismatch is a retrieval failure, not a message.
4. Decrypts the content (strict UTF-8).
5. Verifies `signature_bytes` under the owner's messaging key (`M_self` or `M_peer`), with the
   recipient being the other participant. A failed check yields the message with `verified = false`.

## 6. Prepared messages

A v2 prepared message uses the v1 prepared envelope with envelope version byte `2`, its owner and
recipient being identity keys, its payload being the exact v2 message bytes, and its binding signed
with the owner's messaging seed instead of the identity secret. The envelope does not carry `M`, so
a restored envelope is authenticated against the owner's messaging key; publication does so with
the local messaging key before any request. Publication derives the destination from the local
identity, the local messaging key and the recipient's key record.

## 7. Discovery

Conversation directories are named by a value only the two participants can compute, so there is
no inbox. A client learns about incoming conversations by checking candidate peers (for example
follows and followers): fetch the peer's key record, compute `dir`, and list
`pubky://<peer><dir>`. An empty listing or 404 means the peer has not written to the conversation;
only entries that pass the strict entry filter count.

## 8. Security notes

- Revoking a grant cannot take back a delivered messaging seed. Rotation needs a new
  `MESSAGING_KEY_PATH` and a new protocol revision.
- Directory names, message counts, sizes and plaintext timestamps remain visible to anyone.
- No forward secrecy, as in v1.
