//! Core wire contracts, Sealed Sender envelope validators, and declarative
//! Sonaraim Card verification primitives.
//!
//! This crate enforces the foundational security invariants of the Sonaraim
//! protocol with audited cryptographic dependencies
//! (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `hmac`,
//! `sha2`, `rand`, `subtle`, `zeroize`):
//! - [`card`]: Declarative B2B rich cards with `did:web:` / `did:sonaraim:`
//!   `Ed25519` merchant signatures and strict anti-XSS component checks.
//! - [`jcs`]: RFC 8785 canonical JSON subset shared by signers and verifiers.
//! - [`crypto`]: Audited-crate signing, AEAD sealing, and key derivation.
//! - [`envelope`]: Blinded Sealed Sender envelopes with 32-byte X25519
//!   ephemeral public keys, custom group-ratchet ciphertext bounds, and TTL
//!   validation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod card;
pub mod crypto;
pub mod envelope;
pub mod jcs;
pub mod keyring;
pub mod mls_group;
pub mod oprf;
pub mod psi;
pub mod replay;
pub mod wasm;
pub mod wasm_bridge;
pub mod wasm_json;
pub mod wasm_model;
pub mod wasm_parse;
pub mod wire;

pub use card::{
    validate_card, CardComponent, CardValidationError, ComponentType, MerchantSignature,
    SonaraimCard,
};
pub use envelope::{validate_envelope, EnvelopeValidationError, SealedEnvelope};
pub use jcs::{
    canonical_card_bytes, card_signing_preimage as jcs_signing_preimage, escape_jcs_str,
};
pub use keyring::{KeyEntry, KeyRing, KeyRingError};
pub use replay::{ReplayError, ReplayWindow};
