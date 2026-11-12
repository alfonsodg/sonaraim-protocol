//! Core wire contracts, Sealed Sender envelope validators, and declarative
//! Sonaraim Card verification primitives.
//!
//! This crate enforces the foundational security invariants of the Sonaraim
//! protocol without external runtime dependencies:
//! - [`card`]: Declarative B2B rich cards with `did:web:` / `did:sonaraim:`
//!   `Ed25519` merchant signatures and strict anti-XSS component checks.
//! - [`envelope`]: Blinded Sealed Sender envelopes with 32-byte X25519
//!   ephemeral public keys, MLS ciphertext bounds, and TTL validation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod card;
pub mod crypto;
pub mod envelope;
pub mod mls_group;
pub mod psi;
pub mod replay;
pub mod wire;

pub use card::{
    validate_card, CardComponent, CardValidationError, ComponentType, MerchantSignature,
    SonaraimCard,
};
pub use envelope::{validate_envelope, EnvelopeValidationError, SealedEnvelope};
pub use replay::{ReplayError, ReplayWindow};
