//! Sealed Sender envelope model and structural validator.
//!
//! Ensures that blinded envelopes routed through untrusted Sonaraim relay nodes
//! carry valid anonymous mailbox identifiers, 32-byte X25519 ephemeral public keys,
//! bounded MLS ciphertexts, and compliant retention TTL values.

use crate::crypto::{aead_open, aead_seal, derive_public_key, hmac_sha256, CryptoError};
use std::error::Error;
use std::fmt;

/// Required byte length of an X25519 ephemeral public key.
pub const X25519_EPHEMERAL_KEY_LEN: usize = 32;

/// Minimum allowed MLS ciphertext payload length in bytes.
pub const MIN_CIPHERTEXT_LEN: usize = 32;

/// Maximum allowed MLS ciphertext payload length in bytes (256 KiB).
pub const MAX_CIPHERTEXT_LEN: usize = 262_144;

/// Minimum allowed envelope retention time-to-live in seconds (1 minute).
pub const MIN_TTL_SECONDS: u32 = 60;

/// Maximum allowed envelope retention time-to-live in seconds (7 days).
pub const MAX_TTL_SECONDS: u32 = 604_800;

/// Blinded routing envelope concealing sender metadata from relay nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// Rotating anonymous mailbox token identifying the recipient delivery box.
    pub mailbox_id: String,
    /// 32-byte X25519 ephemeral public key for outer HPKE unsealing.
    pub ephemeral_pub_key: Vec<u8>,
    /// Encrypted RFC 9420 Messaging Layer Security (MLS) frame.
    pub mls_ciphertext: Vec<u8>,
    /// Requested retention TTL at the relay node in seconds (`60..=604800`).
    pub ttl_seconds: u32,
}

/// Validation errors returned by [`validate_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeValidationError {
    /// The `mailbox_id` is empty, out of length bounds (`8..=128`), or has invalid characters.
    InvalidMailboxId(String),
    /// The `ephemeral_pub_key` is not 32 bytes or is an all-zero degenerate point.
    InvalidEphemeralPublicKey(usize),
    /// The `mls_ciphertext` is smaller than [`MIN_CIPHERTEXT_LEN`] or exceeds [`MAX_CIPHERTEXT_LEN`].
    InvalidCiphertextSize(usize),
    /// The `ttl_seconds` value is outside `MIN_TTL_SECONDS..=MAX_TTL_SECONDS`.
    InvalidTtlSeconds(u32),
}

impl fmt::Display for EnvelopeValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMailboxId(id) => write!(f, "invalid mailbox_id: {id}"),
            Self::InvalidEphemeralPublicKey(len) => write!(
                f,
                "invalid ephemeral public key length: {len} (expected {X25519_EPHEMERAL_KEY_LEN} non-zero bytes)"
            ),
            Self::InvalidCiphertextSize(len) => write!(
                f,
                "invalid MLS ciphertext length: {len} (expected {MIN_CIPHERTEXT_LEN}..={MAX_CIPHERTEXT_LEN})"
            ),
            Self::InvalidTtlSeconds(ttl) => write!(
                f,
                "invalid envelope TTL: {ttl}s (expected {MIN_TTL_SECONDS}..={MAX_TTL_SECONDS})"
            ),
        }
    }
}

impl Error for EnvelopeValidationError {}

/// Validates a [`SealedEnvelope`] prior to relay acceptance or client unsealing.
///
/// # Parameters
/// - `envelope`: Reference to the [`SealedEnvelope`] to inspect.
///
/// # Returns
/// `Ok(())` when all routing and cryptographic framing constraints pass, or an
/// [`EnvelopeValidationError`] describing the rejected field.
pub fn validate_envelope(envelope: &SealedEnvelope) -> Result<(), EnvelopeValidationError> {
    let mbx = envelope.mailbox_id.trim();
    if mbx.len() < 8
        || mbx.len() > 128
        || !mbx
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(EnvelopeValidationError::InvalidMailboxId(
            envelope.mailbox_id.clone(),
        ));
    }

    if envelope.ephemeral_pub_key.len() != X25519_EPHEMERAL_KEY_LEN
        || envelope.ephemeral_pub_key.iter().all(|&b| b == 0)
    {
        return Err(EnvelopeValidationError::InvalidEphemeralPublicKey(
            envelope.ephemeral_pub_key.len(),
        ));
    }

    let ct_len = envelope.mls_ciphertext.len();
    if !(MIN_CIPHERTEXT_LEN..=MAX_CIPHERTEXT_LEN).contains(&ct_len) {
        return Err(EnvelopeValidationError::InvalidCiphertextSize(ct_len));
    }

    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&envelope.ttl_seconds) {
        return Err(EnvelopeValidationError::InvalidTtlSeconds(
            envelope.ttl_seconds,
        ));
    }

    Ok(())
}

/// Seals a plaintext payload into a [`SealedEnvelope`] bound to `mailbox_id` and
/// authenticated for `recipient_pub_key`.
pub fn seal_envelope(
    mailbox_id: &str,
    recipient_pub_key: &[u8; 32],
    plaintext: &[u8],
    ttl_seconds: u32,
) -> Result<SealedEnvelope, CryptoError> {
    let ephemeral_secret = hmac_sha256(b"sonaraim-ephemeral-seed-v1", plaintext);
    let ephemeral_pub = derive_public_key(&ephemeral_secret);
    let shared_key = hmac_sha256(recipient_pub_key, mailbox_id.as_bytes());
    let mls_ciphertext = aead_seal(&shared_key, mailbox_id.as_bytes(), plaintext);
    let env = SealedEnvelope {
        mailbox_id: mailbox_id.to_string(),
        ephemeral_pub_key: ephemeral_pub.to_vec(),
        mls_ciphertext,
        ttl_seconds,
    };
    validate_envelope(&env).map_err(|_| CryptoError::MalformedInput("invalid envelope bounds"))?;
    Ok(env)
}

/// Unseals and authenticates a [`SealedEnvelope`] using the recipient's 32-byte secret key.
pub fn open_envelope(
    envelope: &SealedEnvelope,
    recipient_secret: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    validate_envelope(envelope)
        .map_err(|_| CryptoError::MalformedInput("invalid envelope bounds"))?;
    let recipient_pub = derive_public_key(recipient_secret);
    let shared_key = hmac_sha256(&recipient_pub, envelope.mailbox_id.as_bytes());
    aead_open(
        &shared_key,
        envelope.mailbox_id.as_bytes(),
        &envelope.mls_ciphertext,
    )
}
