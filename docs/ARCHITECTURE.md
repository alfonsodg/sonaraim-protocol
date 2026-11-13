# Protocol Architecture — `sonaraim-protocol`

> Wire specifications, Sealed Sender cryptographic framing, and Sonaraim Card validation architecture.

## 1. Architectural Overview

`sonaraim-protocol` provides the foundational wire contracts and cryptographic invariants for the Sonaraim privacy-preserving messaging ecosystem. It strictly separates untrusted relay transport (`SealedEnvelope`) from end-to-end encrypted application payloads (`SonaraimCard` and MLS application frames).

```text
+-------------------------------------------------------------------+
|                        SealedEnvelope                             |
|  +--------------------+----------------------------------------+  |
|  | mailbox_id (anon)  | ephemeral_pub_key (32B X25519)         |  |
|  +--------------------+----------------------------------------+  |
|  | ttl_seconds        | mls_ciphertext (RFC 9420 MLS Frame)    |  |
|  +--------------------+----------------------------------------+  |
|                                  |                                |
|                                  v (Decrypted only by Recipient)  |
|  +-------------------------------------------------------------+  |
|  |                       SonaraimCard                          |  |
|  |  - card_id, title, summary, action components               |  |
|  |  - merchant_signature: DID (did:web / did:sonaraim) + Ed25519|  |
|  +-------------------------------------------------------------+  |
+-------------------------------------------------------------------+
```

---

## 2. Sealed Sender Envelope (`src/envelope.rs`)

Relay nodes route messages exclusively by `mailbox_id` without learning the sender's identity or correlating traffic:

- **`mailbox_id`**: Rotating opaque token (8 to 128 ASCII alphanumeric/hyphen/underscore characters) derived for the recipient's delivery mailbox.
- **`ephemeral_pub_key`**: Exactly 32 bytes representing a one-time X25519 public key used for HPKE/ECDH unsealing.
- **`mls_ciphertext`**: Non-empty encrypted Messaging Layer Security (RFC 9420) payload capped at 256 KiB (`262144` bytes).
- **`ttl_seconds`**: Ephemeral storage TTL between 60 seconds (1 minute) and 604800 seconds (7 days).

---

## 3. Declarative Sonaraim Cards (`src/card.rs`)

B2B merchants send rich interactive messages inside E2EE sessions using declarative JSON schemas rather than embedded WebViews:

- **Strict Component Whitelist**: Only `TextBlock`, `MediaImage`, `KeyValueRow`, and `ActionButton` are constructible and valid. Raw HTML tags (`<script>`, `<iframe>`) and script execution are rejected at validation time.
- **URI Sanitization**: Action and media URLs must start with `https://` or `sonaraim://`. Schemes like `javascript:`, `data:`, or `http://` are rejected immediately.
- **DID Signature Enforcement**: Cards must include a `MerchantSignature` referencing `did:web:<domain>` or `did:sonaraim:<id>`, using algorithm `Ed25519`, with a 128-character hexadecimal signature verified against the canonical JCS digest.

---

## 4. Canonical Hashing & Cryptography (`src/crypto.rs`)

- **JCS Canonicalization (RFC 8785)**: JSON objects are serialized into deterministic UTF-8 byte streams with sorted keys and whitespace normalization before computing digests.
- **AEAD Sealing**: Ephemeral session sealing uses ChaCha20-Poly1305 with 12-byte random nonces and 16-byte poly1305 authentication tags.
- **Digital Signatures**: All cryptographic identity proofs use Ed25519 (Edwards-curve Digital Signature Algorithm).

---

## 5. Identity Keyring & Lifecycle (`src/keyring.rs`)

The `Keyring` subsystem tracks active and historical cryptographic keys for verified DIDs:

```text
[Active Key] ---> [Rotated Key (Historical)] ---> [Revoked Key (Invalid)]
      |                       |                               |
  Signs New               Verifies Past                   Rejects All
  Messages                Signatures                      Signatures
```

- **Rotation**: Keys can be rotated to new key commitments while retaining historical verification capabilities for audit trails.
- **Revocation**: Compromised or decommissioned keys are explicitly revoked with timestamped revocation records.
- **Validity Windows**: Signatures must fall within the `valid_from` and `valid_until` unix epoch timestamps of the key.

---

## 6. MLS Group Ratcheting (`src/mls_group.rs`)

`MlsGroupSession` implements tree ratcheting semantics matching RFC 9420:

- **Epoch Progression**: Adding or removing group members increments the group epoch and updates the epoch secret via HKDF-SHA256.
- **Forward Secrecy**: Old epoch secrets are zeroized upon progression, preventing compromise of past messages if a current device key is extracted.
- **Post-Compromise Security (PCS)**: Members periodically commit self-updates that refresh the tree ratchet and heal past compromises.
- **Transcript Hashing**: Every epoch generates a deterministic transcript hash tying member actions and state transitions together.

---

## 7. Private Set Intersection (`src/psi.rs`)

Private contact discovery enables users to discover contacts already registered on Sonaraim without uploading address books:

- **Blinded Tokens**: The client hashes phone numbers in E.164 format with a client blinding factor.
- **Server Evaluation**: The server evaluates blinded tokens against its internal registered phone index using keyed HMAC or scalar multiplication.
- **Zero Leakage**: Non-matching contacts are completely undetectable by the server.

---

## 8. Anti-Replay Sliding Window (`src/replay.rs`)

The `ReplayWindow` protects nodes and clients against packet replay and duplicate injection:

- **FIFO Eviction**: Maintains a bounded ring-buffer of recently observed envelope IDs.
- **Stale Epoch Rejection**: Messages with epoch values older than the window horizon are rejected.
- **Deterministic Deduplication**: Duplicate envelope IDs within the active window trigger immediate `ReplayError::DuplicateEnvelope`.

---

## 9. Length-Prefixed Wire Framing (`src/wire.rs`)

For stream-oriented transports (TCP, QUIC streams), `wire.rs` provides deterministic frame framing:

- **Header**: 4-byte big-endian payload length header (`u32`).
- **Payload**: Wire-encoded Protobuf or JSON envelope.
- **Truncation Protection**: Receivers detect incomplete frames and buffer incoming bytes until full frames arrive.
