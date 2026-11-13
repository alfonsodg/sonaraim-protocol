# Sonaraim Protocol (`sonaraim-protocol`)

> Zero-metadata Sealed Sender wire contracts, MLS key package models, and declarative Sonaraim Card validators.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Crate: Rust 2021](https://img.shields.io/badge/Crate-Rust%202021-DEA584.svg?logo=rust&logoColor=white)](Cargo.toml)
[![Crypto: OpenMLS RFC 9420](https://img.shields.io/badge/Crypto-OpenMLS%20RFC%209420-orange.svg)](src/mls_group.rs)
[![Schema: JSON Schema 2020-12](https://img.shields.io/badge/Schema-JSON%20Schema%202020--12-informational.svg)](configs/schemas/sonaraim-card.schema.json)
[![Security: Zero-Metadata Sealed Sender](https://img.shields.io/badge/Security-Zero--Metadata%20Sealed%20Sender-green.svg)](SECURITY.md)

`sonaraim-protocol` defines the canonical wire format, cryptographic envelope invariants, and verifiable rich-card schema for the Sonaraim privacy-preserving messaging ecosystem.

---

## ⚡ Key Capabilities

- **Sealed Sender Envelopes (`src/envelope.rs`)**: Blinded routing contracts using anonymous mailbox identifiers, 32-byte X25519 ephemeral public keys, and RFC 9420 MLS ciphertexts.
- **Declarative Sonaraim Cards (`src/card.rs`)**: Safe, interactive B2B message cards that disallow raw HTML, scripts, and unsafe URI schemes at the protocol boundary.
- **Canonical JCS & Ed25519 Signatures (`src/card.rs`, `src/crypto.rs`)**: Deterministic JSON Canonicalization Scheme (RFC 8785) hashing and Ed25519 signature validation bound to `did:web:` and `did:sonaraim:` identifiers.
- **Identity Keyring & Revocation (`src/keyring.rs`)**: Key rotation tracking, expiration checks, and historical signature verification across key lifetimes.
- **MLS Group Ratcheting (`src/mls_group.rs`)**: Group epoch progression, member addition/removal with forward secrecy, post-compromise security ratchets, and transcript hashing.
- **Private Set Intersection (`src/psi.rs`)**: Blinded cryptographic token evaluation for private social graph discovery without leaking unhashed contact books.
- **Anti-Replay Sliding Window (`src/replay.rs`)**: FIFO sliding window for duplicate envelope detection and stale epoch rejection.
- **Wire Framing & Length Prefixing (`src/wire.rs`)**: Binary length-prefixed framing and stream serialization for high-throughput network transports.

---

## 🔐 Cryptographic Framing & Wire Pipeline

The following ASCII diagram illustrates the wire serialization, sealing, and validation flow across the protocol boundaries:

```text
+-----------------------------------------------------------------------------------+
|                        SONARAIM PROTOCOL WIRE PIPELINE                            |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [B2B Application / Client]                     [Declarative Interactive Card]    |
|  - Plaintext Message / Notification             - Strict JSON Schema (2020-12)    |
|  - did:web / did:sonaraim Identity              - Zero-HTML / Zero-Script safety  |
|            |                                              |                       |
|            v                                              v                       |
|  +--------------------+                         +-------------------+             |
|  | OpenMLS RFC 9420   |                         |  Canonical JCS    |             |
|  | Group Ratchet      |                         |  (RFC 8785 Hash)  |             |
|  +---------+----------+                         +---------+---------+             |
|            |                                              |                       |
|            | Ratcheted MLS Ciphertext                     | Ed25519 Signature     |
|            v                                              v                       |
|  +------------------------------------------------------------------+             |
|  |              SEALED SENDER ENVELOPE (src/envelope.rs)            |             |
|  |  - Anonymous Mailbox ID (32-byte Blake3 / SHA-256 routing token) |             |
|  |  - Ephemeral X25519 Public Key (forward secrecy per envelope)    |             |
|  |  - Encrypted Payload Envelope (MLS ciphertext + signed Card)     |             |
|  |  - Anti-Replay Timestamp & Epoch nonce                           |             |
|  +---------------------------------+--------------------------------+             |
|                                    |                                              |
|                                    v                                              |
|  +------------------------------------------------------------------+             |
|  |              LENGTH-PREFIXED WIRE FRAMING (src/wire.rs)          |             |
|  |  [4-byte BE Length Prefix] || [Protobuf / Binary Wire Envelope]  |             |
|  +---------------------------------+--------------------------------+             |
|                                    |                                              |
|            +-----------------------+-----------------------+                      |
|            | Dispatched via QUIC / HTTP                    |                      |
|            v                                               v                      |
|  +-------------------+                           +--------------------+           |
|  |   sonaraim-node   |                           |    Recipient App   |           |
|  |  (Relay Routing)  |                           |  (OpenMLS Unseal)  |           |
|  +-------------------+                           +--------------------+           |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

> [!NOTE]
> For comprehensive sequence diagrams of group ratchet epoch transitions and Sealed Sender validation state machines, see [docs/DIAGRAMS.md](docs/DIAGRAMS.md).

---

## 🧩 Repository Layout

```text
sonaraim-protocol/
├── configs/
│   ├── proto/sonaraim.proto              # Protobuf v3 wire definitions
│   └── schemas/sonaraim-card.schema.json # JSON Schema for Sonaraim Cards
├── docs/
│   ├── ARCHITECTURE.md                   # Protocol design and ASCII layouts
│   ├── DIAGRAMS.md                       # Mermaid sequence and state diagrams
│   └── STANDARDS.md                      # Coding, testing, and linting rules
├── src/
│   ├── card.rs                           # Sonaraim Card model and validator
│   ├── crypto.rs                         # AEAD sealing, unsealing & signatures
│   ├── envelope.rs                       # SealedEnvelope model and validator
│   ├── keyring.rs                        # Key rotation and revocation management
│   ├── lib.rs                            # Crate root and public re-exports
│   ├── mls_group.rs                      # MLS group ratchet state and transcripts
│   ├── psi.rs                            # Private Set Intersection token hashing
│   ├── replay.rs                         # Anti-replay FIFO sliding window
│   └── wire.rs                           # Length-prefixed framing codec
├── tests/
│   ├── milestone1_test.rs                # Phase 1 crypto & envelope tests
│   ├── milestone7_test.rs                # Replay window and test vectors
│   ├── milestone12_test.rs               # Keyring and MLS recovery tests
│   └── protocol_test.rs                  # Core card and envelope validation tests
├── Cargo.toml                            # Rust crate manifest (Apache-2.0)
├── CODE_OF_CONDUCT.md                    # Contributor Covenant v2.1
├── CONTRIBUTING.md                       # Development, TDD & git workflow guide
├── LICENSE                               # Apache License 2.0
└── SECURITY.md                           # Vulnerability disclosure & E2EE scope
```

---

## 🚀 Quick Start

### Build & Test

```bash
# 1. Format check
cargo fmt --check

# 2. Static analysis
cargo clippy --all-targets -- -D warnings

# 3. Test execution
cargo test

# 4. Markdown linting
npx --yes markdownlint-cli2 "*.md" "docs/*.md"
```

---

## 🌐 Collaboration & Governance

- **[Contributing Guide](CONTRIBUTING.md)** — Branching model (`develop`), TDD mandate, and commit conventions.
- **[Code of Conduct](CODE_OF_CONDUCT.md)** — Community standards and enforcement guidelines.
- **[Security Policy](SECURITY.md)** — Vulnerability reporting, SLAs, and cryptographic threat model.
- **[Architecture Specification](docs/ARCHITECTURE.md)** — In-depth protocol framing and ASCII layouts.
- **[System Diagrams](docs/DIAGRAMS.md)** — Mermaid sequence and state diagrams.
- **[Coding Standards](docs/STANDARDS.md)** — Detailed engineering rules and guidelines.

---

## 📜 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

Copyright 2026 Sonaraim Contributors.
