//! Key-ID (`kid`) rotation keyring and timestamp-bounded key-expiration validator.
//!
//! Enables merchants, B2B gateways, and relay nodes to manage versioned signing keys,
//! rotate the active signing key without breaking in-flight signatures, and reject
//! expired, not-yet-valid, or explicitly revoked keys.

use crate::card::SonaraimCard;
use crate::crypto::{
    constant_time_eq, derive_public_key, sign_card_jcs, verify_card_jcs, CryptoError,
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

/// Versioned cryptographic key entry managed inside a [`KeyRing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// Unique key identifier (`kid`).
    pub kid: String,
    /// 32-byte secret key material used to sign or derive public verification keys.
    pub key_bytes: [u8; 32],
    /// Inclusive start timestamp (Unix epoch milliseconds) when the key becomes valid.
    pub not_before_ms: u64,
    /// Inclusive end timestamp (Unix epoch milliseconds) after which the key is expired.
    pub expires_at_ms: u64,
    /// Explicit revocation flag; revoked keys cannot sign or verify cards.
    pub revoked: bool,
}

/// Errors returned by [`KeyRing`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRingError {
    /// The requested `kid` is empty or does not exist in the keyring.
    UnknownKeyId(String),
    /// The key is outside its validity window (`not_before_ms..=expires_at_ms`).
    KeyExpired {
        /// Key identifier that failed the validity check.
        kid: String,
        /// Evaluation timestamp in milliseconds.
        now_ms: u64,
        /// Start of validity window in milliseconds.
        not_before_ms: u64,
        /// End of validity window in milliseconds.
        expires_at_ms: u64,
    },
    /// The key has been explicitly revoked.
    KeyRevoked(String),
    /// Attempted to sign without configuring an active key ID.
    NoActiveKey,
    /// Key validity window has `expires_at_ms < not_before_ms`.
    InvalidTimeBounds(String),
    /// Underlying JCS card signing or verification failure.
    Crypto(CryptoError),
}

impl fmt::Display for KeyRingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKeyId(kid) => write!(f, "unknown key ID: {kid}"),
            Self::KeyExpired {
                kid,
                now_ms,
                not_before_ms,
                expires_at_ms,
            } => write!(
                f,
                "key {kid} not valid at {now_ms}ms (window {not_before_ms}..={expires_at_ms})"
            ),
            Self::KeyRevoked(kid) => write!(f, "key ID is revoked: {kid}"),
            Self::NoActiveKey => write!(f, "no active signing key configured in keyring"),
            Self::InvalidTimeBounds(kid) => write!(f, "invalid time bounds for key ID: {kid}"),
            Self::Crypto(err) => write!(f, "keyring cryptographic error: {err}"),
        }
    }
}

impl Error for KeyRingError {}

/// Multi-key rotation store supporting active key selection, revocation, and TTL validation.
#[derive(Debug, Clone, Default)]
pub struct KeyRing {
    keys: HashMap<String, KeyEntry>,
    active_kid: Option<String>,
}

impl KeyRing {
    /// Creates an empty [`KeyRing`] with no active key.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or updates a [`KeyEntry`] in the keyring.
    pub fn add_key(&mut self, entry: KeyEntry) -> Result<(), KeyRingError> {
        let kid = entry.kid.trim().to_string();
        if kid.is_empty() {
            return Err(KeyRingError::UnknownKeyId(String::new()));
        }
        if entry.expires_at_ms < entry.not_before_ms {
            return Err(KeyRingError::InvalidTimeBounds(kid));
        }
        let mut normalized = entry;
        normalized.kid = kid.clone();
        self.keys.insert(kid, normalized);
        Ok(())
    }

    /// Sets the active signing `kid` if present and not revoked.
    pub fn set_active_key(&mut self, kid: &str) -> Result<(), KeyRingError> {
        let entry = self
            .keys
            .get(kid)
            .ok_or_else(|| KeyRingError::UnknownKeyId(kid.to_string()))?;
        if entry.revoked {
            return Err(KeyRingError::KeyRevoked(kid.to_string()));
        }
        self.active_kid = Some(kid.to_string());
        Ok(())
    }

    /// Returns the currently active signing `kid`, if configured.
    pub fn active_key_id(&self) -> Option<&str> {
        self.active_kid.as_deref()
    }

    /// Marks the specified `kid` as permanently revoked.
    pub fn revoke_key(&mut self, kid: &str) -> Result<(), KeyRingError> {
        let entry = self
            .keys
            .get_mut(kid)
            .ok_or_else(|| KeyRingError::UnknownKeyId(kid.to_string()))?;
        entry.revoked = true;
        Ok(())
    }

    fn validate_entry_usable(entry: &KeyEntry, now_ms: u64) -> Result<(), KeyRingError> {
        if entry.revoked {
            return Err(KeyRingError::KeyRevoked(entry.kid.clone()));
        }
        if now_ms < entry.not_before_ms || now_ms > entry.expires_at_ms {
            return Err(KeyRingError::KeyExpired {
                kid: entry.kid.clone(),
                now_ms,
                not_before_ms: entry.not_before_ms,
                expires_at_ms: entry.expires_at_ms,
            });
        }
        Ok(())
    }

    /// Signs `card` with the currently active key after verifying it is not revoked or expired at `now_ms`.
    pub fn sign_card_with_active_key(
        &self,
        card: &mut SonaraimCard,
        now_ms: u64,
    ) -> Result<String, KeyRingError> {
        let kid = self
            .active_kid
            .as_deref()
            .ok_or(KeyRingError::NoActiveKey)?;
        let entry = self
            .keys
            .get(kid)
            .ok_or_else(|| KeyRingError::UnknownKeyId(kid.to_string()))?;
        Self::validate_entry_usable(entry, now_ms)?;
        sign_card_jcs(card, &entry.key_bytes).map_err(KeyRingError::Crypto)?;
        Ok(entry.kid.clone())
    }

    /// Verifies `card` and `signature` against the specified `kid` at `now_ms`.
    pub fn verify_card_with_kid(
        &self,
        card: &SonaraimCard,
        kid: &str,
        signature: &str,
        now_ms: u64,
    ) -> Result<(), KeyRingError> {
        let entry = self
            .keys
            .get(kid)
            .ok_or_else(|| KeyRingError::UnknownKeyId(kid.to_string()))?;
        Self::validate_entry_usable(entry, now_ms)?;
        if !constant_time_eq(
            card.merchant_signature.signature_hex.as_bytes(),
            signature.as_bytes(),
        ) {
            return Err(KeyRingError::Crypto(CryptoError::InvalidSignature));
        }
        let pub_key = derive_public_key(&entry.key_bytes);
        verify_card_jcs(card, &pub_key).map_err(KeyRingError::Crypto)
    }
}
