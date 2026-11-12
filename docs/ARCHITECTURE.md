# Protocol Architecture — sonaraim-protocol

> Wire specifications, Sealed Sender cryptographic framing, and Sonaraim Card validation architecture.

## 1. Architectural Overview

`sonaraim-protocol` is the foundational layer of the Sonaraim stack. It separates untrusted relay transport (`SealedEnvelope`) from end-to-end encrypted application payloads (`SonaraimCard` and MLS application frames).

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
|  |  - card_id, title, summary                                  |  |
|  |  - components: [TextBlock | MediaImage | ActionButton | ..] |  |
|  |  - merchant_signature: DID (did:web / did:sonaraim) + Ed25519|  |
|  +-------------------------------------------------------------+  |
+-------------------------------------------------------------------+
```

## 2. Sealed Sender Envelope (`src/envelope.rs`)

Relay nodes route messages exclusively by `mailbox_id` without learning the sender's identity:

- **`mailbox_id`**: Rotating opaque token (8 to 128 ASCII alphanumeric/hyphen/underscore characters) derived for the recipient's delivery box.
- **`ephemeral_pub_key`**: Exactly 32 bytes representing a one-time X25519 public key used for HPKE/ECDH unsealing.
- **`mls_ciphertext`**: Non-empty encrypted Messaging Layer Security (RFC 9420) payload capped at 256 KiB (`262144` bytes).
- **`ttl_seconds`**: Ephemeral storage TTL between 60 seconds (1 minute) and 604800 seconds (7 days).

## 3. Declarative Sonaraim Cards (`src/card.rs`)

B2B merchants send rich interactive messages inside E2EE sessions using declarative JSON/Protobuf schemas rather than embedded webviews:

- **Strict Component Whitelist**: Only `TextBlock`, `MediaImage`, `KeyValueRow`, and `ActionButton` are constructible and valid. Raw HTML and script blocks are rejected both by type and by content inspection.
- **URI Sanitization**: Action and media URLs must start with `https://` or `sonaraim://`. Schemes like `javascript:`, `data:`, or `http://` are rejected.
- **DID Signature Enforcement**: Cards must include a `MerchantSignature` referencing `did:web:<domain>` or `did:sonaraim:<id>`, using algorithm `Ed25519`, with a 128-character hexadecimal signature.
