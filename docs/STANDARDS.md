# Development Standards — sonaraim-protocol

> Engineering, security, and verification standards for the Sonaraim protocol crate.

## Language & Toolchain

- **Language**: Rust (latest stable, `edition = "2021"`).
- **Dependencies**: Zero runtime third-party crates in the core validator to ensure deterministic builds, minimal supply-chain surface, and instant execution.
- **File Size Limit**: Every source and test file must remain strictly under 300 lines with a single clear responsibility.

## Code Quality & Documentation

- **Docstrings Mandatory**: Every public module, struct, enum, field, and function must include Rustdoc (`///` or `//!`) explaining behavior, parameters, and return/error semantics.
- **Error Handling**: Explicit typed error enums implementing `std::fmt::Display` and `std::error::Error`. Never use `unwrap()` or `expect()` in library production code.
- **Formatting & Linting**:
  - `cargo fmt --check` must pass with zero diffs.
  - `cargo clippy -- -D warnings` must pass with zero warnings.
  - `markdownlint` must pass on all Markdown files (`README.md`, `REMOTE.md`, `docs/*.md`).

## Security Invariants

1. **Zero XSS Surface**: `SonaraimCard` validation must reject raw HTML tags (`<script`, `<iframe`, `<object`, `onerror=`, `onload=`), unsafe component types, and non-HTTPS/non-deep-link action URIs (`javascript:`, `data:`, `vbscript:`).
2. **Cryptographic Attribution**: Every `SonaraimCard` must carry a `MerchantSignature` with a valid `did:web:` or `did:sonaraim:` identifier, `Ed25519` algorithm tag, and 64-byte (128 hex characters) signature payload.
3. **Blinded Routing Bounds**: Every `SealedEnvelope` must supply a 32-byte X25519 ephemeral public key, a valid mailbox identifier, non-empty MLS ciphertext within size bounds, and a bounded TTL.

## Git & Issue Workflow

- Branch model: `feature/*` / `fix/*` -> `develop` -> `main`.
- Conventional Commits referencing GitHub issues (`feat(protocol): ... (#1)` with `Ref #1`).
- Issues move to `status::review` once all acceptance criteria are verified.
