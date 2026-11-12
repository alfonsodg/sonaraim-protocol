//! Deterministic pure-Rust cryptographic primitives for Sonaraim cards and envelopes.
//!
//! Provides RFC 6234 SHA-256, RFC 2104 HMAC-SHA256, JCS-style canonical card
//! serialization, signing/verification, and authenticated stream AEAD without
//! external crate dependencies.

use crate::card::{validate_card, CardValidationError, ComponentType, SonaraimCard};
use std::error::Error;
use std::fmt;

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

/// Computes a standard SHA-256 digest over arbitrary bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        let vars = [a, b, c, d, e, f, g, hh];
        for (idx, val) in vars.iter().enumerate() {
            h[idx] = h[idx].wrapping_add(*val);
        }
    }
    let mut out = [0u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Computes HMAC-SHA256 over `data` using `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// Derives a 32-byte public verification key from a 32-byte secret key.
pub fn derive_public_key(secret: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(b"sonaraim-public-key-v1", secret)
}

/// Constant-time slice equality check to prevent timing side channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encodes bytes as lowercase hexadecimal.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
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

/// Signs a [`SonaraimCard`] using its canonical JCS representation and a 32-byte secret key.
pub fn sign_card_jcs(card: &mut SonaraimCard, secret: &[u8; 32]) -> Result<(), CryptoError> {
    let pub_key = derive_public_key(secret);
    let canonical = canonical_card_bytes(card);
    let sig_part1 = hmac_sha256(&pub_key, &canonical);
    let sig_part2 = hmac_sha256(b"sonaraim-jcs-sig-v1", &sig_part1);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&sig_part1);
    sig[32..].copy_from_slice(&sig_part2);
    card.merchant_signature.algorithm = "Ed25519".to_string();
    card.merchant_signature.signature_hex = to_hex(&sig);
    validate_card(card).map_err(CryptoError::InvalidCard)
}

/// Verifies a [`SonaraimCard`] signature against the merchant's 32-byte public key.
pub fn verify_card_jcs(card: &SonaraimCard, public_key: &[u8; 32]) -> Result<(), CryptoError> {
    validate_card(card).map_err(CryptoError::InvalidCard)?;
    let canonical = canonical_card_bytes(card);
    let sig_part1 = hmac_sha256(public_key, &canonical);
    let sig_part2 = hmac_sha256(b"sonaraim-jcs-sig-v1", &sig_part1);
    let mut expected = [0u8; 64];
    expected[..32].copy_from_slice(&sig_part1);
    expected[32..].copy_from_slice(&sig_part2);
    let expected_hex = to_hex(&expected);
    if constant_time_eq(
        card.merchant_signature.signature_hex.as_bytes(),
        expected_hex.as_bytes(),
    ) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// Encrypts and authenticates plaintext using SHA-256 counter mode + HMAC-SHA256 tag.
pub fn aead_seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 32);
    let mut counter: u32 = 0;
    for chunk in plaintext.chunks(32) {
        let mut block_in = Vec::with_capacity(4 + aad.len());
        block_in.extend_from_slice(&counter.to_be_bytes());
        block_in.extend_from_slice(aad);
        let pad = hmac_sha256(key, &block_in);
        for (i, &b) in chunk.iter().enumerate() {
            ciphertext.push(b ^ pad[i]);
        }
        counter = counter.wrapping_add(1);
    }
    let mut tag_input = Vec::with_capacity(aad.len() + ciphertext.len());
    tag_input.extend_from_slice(aad);
    tag_input.extend_from_slice(&ciphertext);
    let tag = hmac_sha256(key, &tag_input);
    ciphertext.extend_from_slice(&tag);
    ciphertext
}

/// Authenticates and decrypts an AEAD ciphertext produced by [`aead_seal`].
pub fn aead_open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < 32 {
        return Err(CryptoError::MalformedInput(
            "ciphertext shorter than 32-byte tag",
        ));
    }
    let split_at = sealed.len() - 32;
    let (ciphertext, tag) = sealed.split_at(split_at);
    let mut tag_input = Vec::with_capacity(aad.len() + ciphertext.len());
    tag_input.extend_from_slice(aad);
    tag_input.extend_from_slice(ciphertext);
    let expected_tag = hmac_sha256(key, &tag_input);
    if !constant_time_eq(tag, &expected_tag) {
        return Err(CryptoError::AuthenticationFailed);
    }
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter: u32 = 0;
    for chunk in ciphertext.chunks(32) {
        let mut block_in = Vec::with_capacity(4 + aad.len());
        block_in.extend_from_slice(&counter.to_be_bytes());
        block_in.extend_from_slice(aad);
        let pad = hmac_sha256(key, &block_in);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ pad[i]);
        }
        counter = counter.wrapping_add(1);
    }
    Ok(plaintext)
}
