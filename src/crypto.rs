//! Audited cryptographic primitives for Sonaraim cards and envelopes.
//!
//! Thin public façade over the [`CryptoProvider`](crate::crypto_provider::CryptoProvider)
//! seam: every operation below delegates to
//! [`default_provider`](crate::crypto_provider::default_provider) (the audited-crate
//! backend: [`ed25519_dalek`] v3 for Ed25519 card signatures (RFC 8032),
//! [`x25519_dalek`] v3 for ephemeral X25519 Diffie-Hellman (RFC 7748),
//! [`chacha20poly1305`] for IETF ChaCha20-Poly1305 AEAD (RFC 8439),
//! HKDF-SHA256 extract/expand via the audited [`hkdf`] crate (RFC 5869)
//! over [`sha2`] for epoch and envelope key derivation, HMAC-SHA256 via the
//! audited [`hmac`] crate (RFC 4231) for PSI blinding, [`rand`] (`OsRng`)
//! for nonces and ephemeral key generation, and [`zeroize`] for epoch-key
//! erasure on group ratchet progression).
//!
//! JCS canonical card serialization is deterministic and versioned
//! (`SONARAIM_JCS_VERSION = "sonaraim-jcs-v1"`); the version string is bound
//! into every signature via a domain-separated context.
//!
//! ## Cross-runtime verification (Node.js, no execution here)
//!
//! ```bash
//! node scripts/verify-vectors.mjs tests/vectors/v1.json
//! ```
//!
//! The script uses Node WebCrypto (`crypto.webcrypto.subtle`) with the JSON
//! vectors in `tests/vectors/v1.json`: Ed25519 `verify` over the
//! domain-separated signing preimage
//! (`jcs_version + 0x1f + signature_context + 0x1f + canonical_jcs`), RFC 8032
//! reference checks, and audited-crate version pins. It exits non-zero on any
//! mismatch.

use crate::card::CardValidationError;
use crate::crypto_provider::{default_provider, CryptoProvider};
pub use crate::jcs::{canonical_card_bytes, sign_card_jcs, verify_card_jcs};
use std::error::Error;
use std::fmt;

/// JCS canonicalization version bound into signatures and test vectors.
pub const SONARAIM_JCS_VERSION: &str = "sonaraim-jcs-v1";

/// Domain separation context for Ed25519 card signatures.
pub const CARD_SIGNATURE_CONTEXT: &str = "sonaraim-card-ed25519-v1";

/// Domain separation context for envelope ECDH key derivation.
pub const ENVELOPE_KDF_CONTEXT: &str = "sonaraim-envelope-x25519-v1";

/// HKDF info label for Sonaraim Group Ratchet epoch rotation.
pub const GROUP_RATCHET_KDF_INFO: &str = "sonaraim-group-ratchet-v1";

/// Authentication tag length in bytes for ChaCha20-Poly1305 ciphertexts.
pub const AEAD_TAG_LEN: usize = 16;

/// Nonce length in bytes for ChaCha20-Poly1305 IETF AEAD.
pub const AEAD_NONCE_LEN: usize = 12;

/// Cryptographic operation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Card structural validation failed prior to signing or verification.
    InvalidCard(CardValidationError),
    /// The Ed25519/HMAC signature did not match the canonical payload.
    InvalidSignature,
    /// AEAD authentication tag verification failed (tampered or wrong key).
    AuthenticationFailed,
    /// Input key material or ciphertext is malformed or too short.
    MalformedInput(&'static str),
    /// HKDF key derivation failed (e.g. invalid PRK length or oversized output).
    KdfError,
    /// AEAD sealing failed (invalid key, RNG failure, or length overflow).
    SealFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCard(err) => write!(f, "card validation failed: {err}"),
            Self::InvalidSignature => write!(f, "invalid cryptographic signature"),
            Self::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            Self::MalformedInput(msg) => write!(f, "malformed cryptographic input: {msg}"),
            Self::KdfError => write!(f, "HKDF key derivation failed"),
            Self::SealFailed => write!(f, "AEAD sealing failed"),
        }
    }
}

impl Error for CryptoError {}

/// SHA-256 digest over arbitrary bytes (audited [`sha2`] crate via the provider).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    default_provider().sha256(data)
}

/// HMAC-SHA256 over `data` using `key` (used for PSI blinding tokens).
///
/// Backed by the audited [`hmac`] crate (RFC 4231) via the provider.
/// Key preprocessing (hash-then-pad for oversized keys) follows the crate's
/// RFC-compliant construction rather than a hand-rolled block loop
/// (protocol#8).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    default_provider().hmac_sha256(key, data)
}

/// Returns the Ed25519 verification key bytes for a 32-byte signing seed.
///
/// Matches RFC 8032 §7.1 test vectors (e.g. seed `9d61b19d…` yields public key
/// `d75a9801…`).
pub fn ed25519_public_key_bytes(seed: &[u8; 32]) -> [u8; 32] {
    default_provider().ed25519_public_key_bytes(seed)
}

/// Signs raw bytes with an Ed25519 32-byte seed (RFC 8032).
pub fn ed25519_sign_bytes(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    default_provider().ed25519_sign_bytes(seed, message)
}

/// Verifies an Ed25519 signature over raw bytes.
pub fn ed25519_verify_bytes(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    default_provider().ed25519_verify_bytes(public_key, message, signature)
}

/// Performs a raw RFC 7748 X25519 ladder step `X25519(k, u)` without clamping.
///
/// Matches the published §6.1 ladder test vectors exactly. For protocol key
/// agreement use [`x25519_agree`], which applies Curve25519 clamping via
/// typed `StaticSecret` keys.
pub fn x25519_raw(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    default_provider().x25519_raw(k, u)
}

/// Performs an X25519 Diffie-Hellman agreement (RFC 7748).
///
/// Returns the 32-byte shared secret for `secret` and the peer public key.
/// Clamps per RFC 7748 via typed curve25519 keys.
pub fn x25519_agree(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    default_provider().x25519_agree(secret, peer_public)
}

/// Generates a fresh random X25519 ephemeral secret via `OsRng`.
/// Uses the `static_secrets` feature so recipient long-term keys stay usable.
pub fn x25519_ephemeral_secret() -> [u8; 32] {
    default_provider().x25519_ephemeral_secret()
}

/// Returns the X25519 public key for a 32-byte secret.
pub fn x25519_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    default_provider().x25519_public_from_secret(secret)
}

/// Derives a 32-byte envelope AEAD key from an X25519 shared secret via HKDF-SHA256.
///
/// Uses the audited [`hkdf`] crate (RFC 5869) via the provider: extract with
/// `ENVELOPE_KDF_CONTEXT` as salt, then single-block expand over `mailbox_id`.
pub fn derive_envelope_key(shared_secret: &[u8; 32], mailbox_id: &[u8]) -> [u8; 32] {
    default_provider().derive_envelope_key(shared_secret, mailbox_id)
}

/// Derives the next Sonaraim Group Ratchet epoch key via HKDF-SHA256.
pub fn derive_epoch_key(prev_key: &[u8; 32], context: &[u8]) -> [u8; 32] {
    default_provider().derive_epoch_key(prev_key, context)
}

/// Deprecated alias of [`jcs::card_signing_preimage`](crate::jcs::card_signing_preimage)
/// with the crate's `SONARAIM_JCS_VERSION`/`CARD_SIGNATURE_CONTEXT` bound in.
/// Kept for existing call-sites and downstream consumers.
pub fn card_signing_preimage(canonical: &[u8]) -> Vec<u8> {
    crate::jcs::card_signing_preimage(canonical, SONARAIM_JCS_VERSION, CARD_SIGNATURE_CONTEXT)
}

/// Decodes 128-char hex into a 64-byte Ed25519 signature.
pub fn decode_signature_hex(hex: &str) -> Result<[u8; 64], CryptoError> {
    if hex.len() != 128 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptoError::InvalidSignature);
    }
    let mut out = [0u8; 64];
    let bytes = hex.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = (bytes[idx] as char)
            .to_digit(16)
            .ok_or(CryptoError::InvalidSignature)? as u8;
        let lo = (bytes[idx + 1] as char)
            .to_digit(16)
            .ok_or(CryptoError::InvalidSignature)? as u8;
        out[idx / 2] = (hi << 4) | lo;
        idx += 2;
    }
    Ok(out)
}

/// Generates a fresh random 12-byte ChaCha20-Poly1305 nonce via `OsRng`.
pub fn fresh_nonce() -> [u8; 12] {
    default_provider().fresh_nonce()
}

/// Encrypts and authenticates plaintext with ChaCha20-Poly1305 (RFC 8439).
///
/// Output layout is `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
/// Sealing failures (RNG failure or length overflow) are returned as
/// [`CryptoError::SealFailed`]; there is no nonce-zero fallback — callers
/// must propagate the error rather than emit unauthenticated bytes
/// (protocol#10).
pub fn aead_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    default_provider().aead_seal(key, aad, plaintext)
}

/// Authenticates and decrypts an AEAD ciphertext produced by [`aead_seal`].
pub fn aead_open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    default_provider().aead_open(key, aad, sealed)
}

/// Constant-time slice equality check to prevent timing side channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    default_provider().constant_time_eq(a, b)
}

/// Encodes bytes as lowercase hexadecimal.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Securely zeroes a 32-byte epoch key in place.
pub fn zeroize_key(key: &mut [u8; 32]) {
    default_provider().zeroize_key(key);
}
