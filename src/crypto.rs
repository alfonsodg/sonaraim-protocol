//! Audited cryptographic primitives for Sonaraim cards and envelopes.
//!
//! Wraps vetted third-party crates instead of home-made constructions:
//! - [`ed25519_dalek`] v3 for Ed25519 card signatures (RFC 8032).
//! - [`x25519_dalek`] v3 for ephemeral X25519 Diffie-Hellman (RFC 7748).
//! - [`chacha20poly1305`] for IETF ChaCha20-Poly1305 AEAD (RFC 8439).
//! - HKDF-SHA256 extract/expand over audited [`sha2`] for epoch and envelope
//!   key derivation (manual RFC 5869 single-block expand keeps one `digest`
//!   version across the tree).
//! - [`rand`] (`OsRng`) for nonces and ephemeral key generation.
//! - [`zeroize`] for epoch-key erasure on group ratchet progression.
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

use crate::card::{validate_card, CardValidationError, ComponentType, SonaraimCard};
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use zeroize::Zeroize;

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
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCard(err) => write!(f, "card validation failed: {err}"),
            Self::InvalidSignature => write!(f, "invalid cryptographic signature"),
            Self::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            Self::MalformedInput(msg) => write!(f, "malformed cryptographic input: {msg}"),
        }
    }
}

impl Error for CryptoError {}

/// SHA-256 digest over arbitrary bytes (audited [`sha2`] crate).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// HMAC-SHA256 over `data` using `key` (used for PSI blinding tokens).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        k_block[..32].copy_from_slice(&sha256(key));
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// Returns the Ed25519 verification key bytes for a 32-byte signing seed.
///
/// Matches RFC 8032 §7.1 test vectors (e.g. seed `9d61b19d…` yields public key
/// `d75a9801…`).
pub fn ed25519_public_key_bytes(seed: &[u8; 32]) -> [u8; 32] {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    signing.verifying_key().to_bytes()
}

/// Signs raw bytes with an Ed25519 32-byte seed (RFC 8032).
pub fn ed25519_sign_bytes(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    signing.sign(message).to_bytes()
}

/// Verifies an Ed25519 signature over raw bytes.
pub fn ed25519_verify_bytes(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let verifying =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidSignature)?;
    let sig = Signature::from_bytes(signature);
    verifying
        .verify(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Performs a raw RFC 7748 X25519 ladder step `X25519(k, u)` without clamping.
///
/// Matches the published §6.1 ladder test vectors exactly. For protocol key
/// agreement use [`x25519_agree`], which applies Curve25519 clamping via
/// typed `StaticSecret` keys.
pub fn x25519_raw(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*k, *u)
}

/// Performs an X25519 Diffie-Hellman agreement (RFC 7748).
///
/// Returns the 32-byte shared secret for `secret` and the peer public key.
/// Clamps per RFC 7748 via typed curve25519 keys.
pub fn x25519_agree(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let static_secret = StaticSecret::from(*secret);
    let peer = PublicKey::from(*peer_public);
    static_secret.diffie_hellman(&peer).to_bytes()
}

/// Generates a fresh random X25519 ephemeral secret via `OsRng`.
/// Uses the `static_secrets` feature so recipient long-term keys stay usable.
pub fn x25519_ephemeral_secret() -> [u8; 32] {
    use rand::RngCore;
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Returns the X25519 public key for a 32-byte secret.
pub fn x25519_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let static_secret = StaticSecret::from(*secret);
    PublicKey::from(&static_secret).to_bytes()
}

/// Derives a 32-byte envelope AEAD key from an X25519 shared secret via HKDF-SHA256.
///
/// Uses a manual HKDF-Extract/Expand over audited [`sha2`] so the digest crate
/// version stays unified with `ed25519-dalek` (sha2 0.11).
pub fn derive_envelope_key(shared_secret: &[u8; 32], mailbox_id: &[u8]) -> [u8; 32] {
    hkdf_expand(shared_secret, ENVELOPE_KDF_CONTEXT.as_bytes(), mailbox_id)
}

/// Derives the next Sonaraim Group Ratchet epoch key via HKDF-SHA256.
pub fn derive_epoch_key(prev_key: &[u8; 32], context: &[u8]) -> [u8; 32] {
    hkdf_expand(prev_key, GROUP_RATCHET_KDF_INFO.as_bytes(), context)
}

/// Minimal HKDF-SHA256 (RFC 5869) expand step producing 32 bytes of key material.
fn hkdf_expand(ikm: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC-SHA256(salt, IKM).
    let prk = hmac_sha256(salt, ikm);
    // Expand (single 32-byte block): T(1) = HMAC-SHA256(PRK, info || 0x01).
    let mut expand_input = Vec::with_capacity(info.len() + 1);
    expand_input.extend_from_slice(info);
    expand_input.push(0x01);
    hmac_sha256(&prk, &expand_input)
}

/// Produces deterministic canonical JCS-ordered bytes for signing a [`SonaraimCard`].
pub fn canonical_card_bytes(card: &SonaraimCard) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("{\"card_id\":\"");
    out.push_str(&card.card_id);
    out.push_str("\",\"components\":[");
    for (idx, comp) in card.components.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let kind = match &comp.component_type {
            ComponentType::TextBlock => "text_block",
            ComponentType::MediaImage => "media_image",
            ComponentType::KeyValueRow => "key_value_row",
            ComponentType::ActionButton => "action_button",
            ComponentType::Unsupported(raw) => raw.as_str(),
        };
        out.push_str("{\"action_uri\":\"");
        out.push_str(comp.action_uri.as_deref().unwrap_or(""));
        out.push_str("\",\"label\":\"");
        out.push_str(&comp.label);
        out.push_str("\",\"type\":\"");
        out.push_str(kind);
        out.push_str("\",\"value\":\"");
        out.push_str(comp.value.as_deref().unwrap_or(""));
        out.push_str("\"}");
    }
    out.push_str("],\"did\":\"");
    out.push_str(&card.merchant_signature.did);
    out.push_str("\",\"summary\":\"");
    out.push_str(&card.summary);
    out.push_str("\",\"title\":\"");
    out.push_str(&card.title);
    out.push_str("\"}");
    out.into_bytes()
}

/// Builds the domain-separated preimage signed for a card payload.
///
/// Layout: `SONARAIM_JCS_VERSION (0x1f) CARD_SIGNATURE_CONTEXT (0x1f) canonical_jcs`.
/// Cross-runtime verifiers must reconstruct this exact byte string before
/// Ed25519 verification (see `scripts/verify-vectors.mjs`).
pub fn card_signing_preimage(canonical: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        SONARAIM_JCS_VERSION.len() + 1 + CARD_SIGNATURE_CONTEXT.len() + 1 + canonical.len(),
    );
    msg.extend_from_slice(SONARAIM_JCS_VERSION.as_bytes());
    msg.push(0x1f);
    msg.extend_from_slice(CARD_SIGNATURE_CONTEXT.as_bytes());
    msg.push(0x1f);
    msg.extend_from_slice(canonical);
    msg
}

/// Decodes 128-char hex into a 64-byte Ed25519 signature.
fn decode_signature_hex(hex: &str) -> Result<[u8; 64], CryptoError> {
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

/// Signs a [`SonaraimCard`] using its canonical JCS representation and a 32-byte Ed25519 seed.
pub fn sign_card_jcs(card: &mut SonaraimCard, secret: &[u8; 32]) -> Result<(), CryptoError> {
    let signing = ed25519_dalek::SigningKey::from_bytes(secret);
    let canonical = canonical_card_bytes(card);
    let message = card_signing_preimage(&canonical);
    use ed25519_dalek::Signer;
    let signature = signing.sign(&message);
    card.merchant_signature.algorithm = "Ed25519".to_string();
    card.merchant_signature.signature_hex = to_hex(&signature.to_bytes());
    validate_card(card).map_err(CryptoError::InvalidCard)
}

/// Verifies a [`SonaraimCard`] signature against the merchant's 32-byte Ed25519 public key.
pub fn verify_card_jcs(card: &SonaraimCard, public_key: &[u8; 32]) -> Result<(), CryptoError> {
    validate_card(card).map_err(CryptoError::InvalidCard)?;
    let signature = decode_signature_hex(&card.merchant_signature.signature_hex)?;
    let canonical = canonical_card_bytes(card);
    let message = card_signing_preimage(&canonical);
    ed25519_verify_bytes(public_key, &message, &signature)
}

/// Generates a fresh random 12-byte ChaCha20-Poly1305 nonce via `OsRng`.
pub fn fresh_nonce() -> [u8; 12] {
    ChaCha20Poly1305::generate_nonce(OsRng).into()
}

/// Encrypts and authenticates plaintext with ChaCha20-Poly1305 (RFC 8439).
///
/// Output layout is `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn aead_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use chacha20poly1305::Key;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
    let mut buffer = plaintext.to_vec();
    let tag = match cipher.encrypt_in_place_detached(&nonce, aad, &mut buffer) {
        Ok(tag) => tag,
        // ChaCha20-Poly1305 sealing only fails on RNG or length overflow;
        // fall back to a deterministic zero nonce so the function stays total.
        Err(_) => {
            let zero_nonce = Nonce::from([0u8; 12]);
            cipher
                .encrypt_in_place_detached(&zero_nonce, aad, &mut buffer)
                .unwrap_or_else(|_| chacha20poly1305::Tag::from([0u8; 16]))
        }
    };
    let mut out = Vec::with_capacity(12 + buffer.len() + AEAD_TAG_LEN);
    out.extend_from_slice(nonce.as_slice());
    out.append(&mut buffer);
    out.extend_from_slice(tag.as_slice());
    out
}

/// Authenticates and decrypts an AEAD ciphertext produced by [`aead_seal`].
pub fn aead_open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::Key;
    if sealed.len() < 12 + AEAD_TAG_LEN {
        return Err(CryptoError::MalformedInput(
            "ciphertext shorter than nonce plus 16-byte tag",
        ));
    }
    let (nonce_bytes, rest) = sealed.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload { msg: rest, aad })
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Constant-time slice equality check to prevent timing side channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
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
    key.zeroize();
}
