//! Internal cryptographic provider seam (issue #17).
//!
//! [`CryptoProvider`] isolates every audited-crate call behind one trait so a
//! future OpenMLS backend swaps a single implementation instead of touching
//! each consumer (`mls_group`, `oprf`, `psi`, `envelope`, `jcs`). The sole
//! production backend is [`AuditedProvider`], built on the current audited
//! set (`ed25519-dalek` v3, `x25519-dalek` v3, `chacha20poly1305`,
//! `hkdf`/`hmac` over `sha2`, `rand`/`OsRng`, `subtle`, `zeroize`).
//! No behavior change, no new dependencies. OpenMLS re-evaluation stays
//! tracked in issue #16.

use crate::crypto::{CryptoError, AEAD_TAG_LEN, ENVELOPE_KDF_CONTEXT, GROUP_RATCHET_KDF_INFO};
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore as _;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Audited-crate backend: the single production [`CryptoProvider`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditedProvider;

/// Returns the production provider (audited-crate backend).
pub fn default_provider() -> AuditedProvider {
    AuditedProvider
}

/// Zeroize-on-drop 32-byte secret wrapper for key material in transit.
///
/// `Debug` is redacted so key material never lands in logs.
pub struct SecretBytes {
    bytes: [u8; 32],
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([redacted; 32])")
    }
}

impl SecretBytes {
    /// Wraps 32 secret bytes; the inner copy is erased on drop.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Borrows the secret bytes without copying.
    pub fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SecretBytes {}

/// Backend-agnostic cryptographic seam for all protocol consumers.
///
/// A future OpenMLS backend implements this trait once; consumers keep
/// calling the same methods. Default methods derive the protocol KDF labels
/// so backends only implement the raw HKDF expand.
pub trait CryptoProvider: Send + Sync {
    /// SHA-256 digest over arbitrary bytes.
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    /// SHA-512 digest over arbitrary bytes (OPRF Elligator-map input).
    fn sha512_64(&self, data: &[u8]) -> [u8; 64];
    /// HMAC-SHA256 over `data` under `key` (RFC 4231, PSI blinding tokens).
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];
    /// Ed25519 verification-key bytes for a 32-byte seed (RFC 8032 §7.1).
    fn ed25519_public_key_bytes(&self, seed: &[u8; 32]) -> [u8; 32];
    /// Ed25519 signature over raw bytes with a 32-byte seed.
    fn ed25519_sign_bytes(&self, seed: &[u8; 32], message: &[u8]) -> [u8; 64];
    /// Ed25519 signature verification over raw bytes.
    fn ed25519_verify_bytes(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError>;
    /// Raw RFC 7748 X25519 ladder step `X25519(k, u)` without clamping.
    fn x25519_raw(&self, k: &[u8; 32], u: &[u8; 32]) -> [u8; 32];
    /// Clamped X25519 Diffie-Hellman agreement for protocol key exchange.
    fn x25519_agree(&self, secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32];
    /// Fresh random X25519 ephemeral secret via the CSPRNG.
    fn x25519_ephemeral_secret(&self) -> [u8; 32];
    /// X25519 public key for a 32-byte secret.
    fn x25519_public_from_secret(&self, secret: &[u8; 32]) -> [u8; 32];
    /// HKDF-SHA256 (RFC 5869): extract with `salt`, expand over `info` to 32 bytes.
    fn hkdf_sha256_32(&self, ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32];
    /// Envelope AEAD key from an X25519 shared secret (envelope KDF context salt).
    fn derive_envelope_key(&self, shared_secret: &[u8; 32], mailbox_id: &[u8]) -> [u8; 32] {
        self.hkdf_sha256_32(shared_secret, ENVELOPE_KDF_CONTEXT.as_bytes(), mailbox_id)
    }
    /// Next group-ratchet epoch key (group-ratchet KDF label salt).
    fn derive_epoch_key(&self, prev_key: &[u8; 32], context: &[u8]) -> [u8; 32] {
        self.hkdf_sha256_32(prev_key, GROUP_RATCHET_KDF_INFO.as_bytes(), context)
    }
    /// Fills `out` with CSPRNG bytes (`OsRng`).
    fn fill_random(&self, out: &mut [u8]);
    /// Fresh random 12-byte ChaCha20-Poly1305 nonce via the CSPRNG.
    fn fresh_nonce(&self) -> [u8; 12];
    /// AEAD seal; output layout is `nonce (12B) || ciphertext || tag (16B)`.
    fn aead_seal(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    /// AEAD open for ciphertexts produced by [`CryptoProvider::aead_seal`].
    fn aead_open(&self, key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Constant-time slice equality (no early exit on mismatch).
    fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool;
    /// Securely zeroes a 32-byte epoch key in place.
    fn zeroize_key(&self, key: &mut [u8; 32]);
}

impl CryptoProvider for AuditedProvider {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn sha512_64(&self, data: &[u8]) -> [u8; 64] {
        let digest = Sha512::digest(data);
        let mut out = [0u8; 64];
        out.copy_from_slice(&digest);
        out
    }

    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts keys of any length");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    fn ed25519_public_key_bytes(&self, seed: &[u8; 32]) -> [u8; 32] {
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    fn ed25519_sign_bytes(&self, seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(seed).sign(message).to_bytes()
    }

    fn ed25519_verify_bytes(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        let verifying =
            VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidSignature)?;
        verifying
            .verify(message, &Signature::from_bytes(signature))
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn x25519_raw(&self, k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
        x25519_dalek::x25519(*k, *u)
    }

    fn x25519_agree(&self, secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
        StaticSecret::from(*secret)
            .diffie_hellman(&PublicKey::from(*peer_public))
            .to_bytes()
    }

    fn x25519_ephemeral_secret(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }

    fn x25519_public_from_secret(&self, secret: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
    }

    fn hkdf_sha256_32(&self, ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm)
            .expect("32-byte HKDF-SHA256 expand must succeed");
        okm
    }

    fn fill_random(&self, out: &mut [u8]) {
        OsRng.fill_bytes(out);
    }

    fn fresh_nonce(&self) -> [u8; 12] {
        ChaCha20Poly1305::generate_nonce(OsRng).into()
    }

    fn aead_seal(
        &self,
        key: &[u8; 32],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::Key;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, &mut buffer)
            .map_err(|_| CryptoError::SealFailed)?;
        let mut out = Vec::with_capacity(12 + buffer.len() + AEAD_TAG_LEN);
        out.extend_from_slice(nonce.as_slice());
        out.append(&mut buffer);
        out.extend_from_slice(tag.as_slice());
        Ok(out)
    }

    fn aead_open(&self, key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::Key;
        if sealed.len() < 12 + AEAD_TAG_LEN {
            return Err(CryptoError::MalformedInput(
                "ciphertext shorter than nonce plus 16-byte tag",
            ));
        }
        let (nonce_bytes, rest) = sealed.split_at(12);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                chacha20poly1305::aead::Payload { msg: rest, aad },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    fn zeroize_key(&self, key: &mut [u8; 32]) {
        key.zeroize();
    }
}
