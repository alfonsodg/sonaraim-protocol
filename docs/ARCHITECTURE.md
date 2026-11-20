# Protocol Architecture — `sonaraim-protocol`

> Wire specifications, Sealed Sender cryptographic framing, and Sonaraim Card validation architecture.

## 1. Architectural Overview

`sonaraim-protocol` provides the foundational wire contracts and cryptographic invariants for the Sonaraim privacy-preserving messaging ecosystem. It strictly separates untrusted relay transport (`SealedEnvelope`) from end-to-end encrypted application payloads (`SonaraimCard` and group-ratchet application frames).

```text
+-------------------------------------------------------------------+
|                        SealedEnvelope                             |
|  +--------------------+----------------------------------------+  |
|  | mailbox_id (anon)  | ephemeral_pub_key (32B X25519)         |  |
|  +--------------------+----------------------------------------+  |
|  | ttl_seconds        | mls_ciphertext (Group Ratchet Frame)   |  |
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
- **`ephemeral_pub_key`**: Exactly 32 bytes representing a fresh random one-time X25519 public key; sealing runs ephemeral-static Diffie-Hellman against the recipient key with HKDF-SHA256 derivation (ECDH, not HPKE).
- **`mls_ciphertext`**: Non-empty encrypted Sonaraim Group Ratchet payload (ChaCha20-Poly1305 AEAD, `nonce || ciphertext || tag`) capped at 256 KiB (`262144` bytes). The field name is historical; the bytes are a custom group-ratchet frame, not an RFC 9420 message.
- **`ttl_seconds`**: Ephemeral storage TTL between 60 seconds (1 minute) and 604800 seconds (7 days).

---

## 3. Declarative Sonaraim Cards (`src/card.rs`)

B2B merchants send rich interactive messages inside E2EE sessions using declarative JSON schemas rather than embedded WebViews:

- **Strict Component Whitelist**: Only `TextBlock`, `MediaImage`, `KeyValueRow`, and `ActionButton` are constructible and valid. Raw HTML tags (`<script>`, `<iframe>`) and script execution are rejected at validation time.
- **URI Sanitization**: Action and media URLs must start with `https://` or `sonaraim://`. Schemes like `javascript:`, `data:`, or `http://` are rejected immediately.
- **DID Signature Enforcement**: Cards must include a `MerchantSignature` referencing `did:web:<domain>` or `did:sonaraim:<id>`, using algorithm `Ed25519`, with a 128-character hexadecimal signature verified against the canonical JCS digest.

---

## 4. Canonical Hashing & Cryptography (`src/crypto.rs`)

Audited crates only (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `curve25519-dalek` for the verifiable OPRF, `hmac`, `hkdf`, `sha2`, `rand`/`OsRng`, `zeroize`); home-made hashes, MACs, and ciphers are forbidden:

- **Canonical JSON serialization (versioned preimage)**: card fields are serialized into deterministic UTF-8 byte streams with fixed key order; the signed preimage is versioned (`sonaraim-jcs-v1` + `0x1f` + `sonaraim-card-ed25519-v1` + `0x1f` + canonical bytes) and pinned in `tests/vectors/v1.json`. This is a protocol-internal deterministic encoding, not a claim of full RFC 8785 JCS conformance.
- **AEAD Sealing**: Envelope sealing uses ChaCha20-Poly1305 (IETF, RFC 8438/8439 layout `nonce || ciphertext || 16-byte tag`) with 12-byte fresh random nonces per seal.
- **Digital Signatures**: All cryptographic identity proofs use real Ed25519 (`ed25519-dalek`, RFC 8032) verified against RFC test vectors; X25519 agreement (`x25519-dalek`, RFC 7748) derives AEAD keys via HKDF-SHA256.

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

## 6. Sonaraim Group Ratcheting (`src/mls_group.rs`)

`MlsGroupState` implements an MLS-inspired (not RFC 9420, not OpenMLS — explicitly deferred) symmetric group ratchet:

- **Epoch Progression**: Adding or removing group members increments the group epoch and updates the epoch secret via HKDF-SHA256.
- **Forward Secrecy**: The superseded transient epoch key copy is zeroized on every rotation, and `force_recovery_ratchet(..., purge_prior_epochs = true)` zeroizes and drops all prior stored epoch keys so compromised history stays unrecoverable.
- **Post-Compromise Security (PCS)**: Members trigger emergency `force_recovery_ratchet` updates with fresh entropy that refresh the ratchet and heal past compromises.
- **Transcript Hashing**: Every epoch generates a deterministic SHA-256 transcript hash tying member actions and state transitions together.

---

## 7. Private Set Intersection (`src/psi.rs`)

Private contact discovery enables users to discover contacts already registered on Sonaraim without uploading address books:

- **Blinded Tokens**: The client hashes phone numbers in E.164 format with a per-session client salt (`HMAC-SHA256` blinding, no server secret on the client).
- **Server Evaluation**: The server returns keyed tokens for client blinds plus directory commitments salted with the client salt; matching is an honest DH-blinded intersection run entirely on the client (`match_psi_results` never receives `server_secret`).
- **Zero Leakage**: Non-matching contacts are completely undetectable by the server; malicious-server security (verifiable OPRF) is deferred follow-up work, not claimed here.

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
