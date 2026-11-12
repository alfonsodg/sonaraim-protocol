# Sonaraim Protocol

> Zero-metadata Sealed Sender wire contracts, MLS key package models, and declarative Sonaraim Card validators.

`sonaraim-protocol` defines the canonical wire format, cryptographic envelope invariants, and verifiable rich-card schema for the Sonaraim privacy-preserving messaging ecosystem.

## Key Capabilities

- **Sealed Sender Envelopes**: Blinded routing contracts using anonymous mailbox identifiers, 32-byte X25519 ephemeral public keys, and MLS (RFC 9420) ciphertexts.
- **Declarative Sonaraim Cards**: Safe, interactive B2B message cards that disallow raw HTML, scripts, and unsafe URI schemes at the protocol boundary.
- **Verifiable Merchant Signatures**: Enforces `did:web:` and `did:sonaraim:` Decentralized Identifiers paired with `Ed25519` cryptographic signatures.
- **Zero-Dependency Core Validator**: Lightweight Rust library crate built purely on `std` for deterministic, sub-second builds and WASM/FFI portability.

## Repository Layout

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
│   ├── lib.rs                            # Crate root and re-exports
│   ├── card.rs                           # Sonaraim Card model and validator
│   └── envelope.rs                       # SealedEnvelope model and validator
└── tests/
    └── protocol_test.rs                  # Integration and security test suite
```

## Quick Start

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

## License

Dual-licensed under MIT or Apache-2.0.
