//! Verifiable 2HashDH OPRF for malicious-server PSI security.
//!
//! The client blinds the phone-derived ristretto255 element with a fresh
//! scalar, the server evaluates with its static key and attaches a
//! Chaum-Pedersen DLEQ proof binding the evaluation to its published public
//! key `K = k * G`, and the client verifies the proof before deriving the
//! HKDF-SHA256 match token. A server that substitutes tokens fails proof
//! verification instead of silently biasing the intersection.
//!
//! The legacy HMAC helpers in [`crate::psi`] stay available for migration;
//! new deployments must prefer this module. OpenMLS (RFC 9420) group key
//! agreement remains deferred per `docs/STANDARDS.md`.

use crate::crypto::GROUP_RATCHET_KDF_INFO;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore as _;
use sha2::{Digest, Sha512};
use std::error::Error;
use std::fmt;

/// Domain separation tag hashing phone bytes to a ristretto255 element.
pub const OPRF_HASH_DST: &str = "sonaraim-oprf-v1-h1";
/// Domain separation tag for HKDF-SHA256 match-token expansion.
pub const OPRF_TOKEN_INFO: &str = "sonaraim-oprf-v1-token";
/// Domain separation tag for the DLEQ proof challenge transcript.
pub const OPRF_PROOF_DST: &str = "sonaraim-oprf-v1-dleq";
/// Byte length of a compressed ristretto255 element or scalar.
pub const OPRF_ELEMENT_LEN: usize = 32;

/// Errors returned by verifiable OPRF operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OprfError {
    /// A wire element was not a canonical ristretto255 encoding.
    InvalidElement,
    /// Server evaluation failed verification against its public key.
    VerificationFailed,
}

impl fmt::Display for OprfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidElement => write!(f, "invalid ristretto255 OPRF element"),
            Self::VerificationFailed => {
                write!(f, "OPRF evaluation failed server-key verification")
            }
        }
    }
}

impl Error for OprfError {}

/// Server evaluation with an attached DLEQ proof, all fixed-size wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OprfEvaluation {
    /// Compressed evaluated element `Z = k * B`.
    pub evaluated: [u8; OPRF_ELEMENT_LEN],
    /// Proof challenge binding `(G, K, B, Z, A1, A2)`.
    pub proof_challenge: [u8; OPRF_ELEMENT_LEN],
    /// Proof response `s = t - c * k`.
    pub proof_response: [u8; OPRF_ELEMENT_LEN],
}

/// Hashes input bytes to a ristretto255 point via SHA-512 Elligator map.
///
/// Uses `from_uniform_bytes` over our SHA-512 digest (two Elligator maps +
/// addition), so the discrete log of the output with respect to any other
/// point is unknown. Avoids `hash_from_bytes`, whose `digest` 0.11 bound is
/// incompatible with the crate's pinned `sha2` 0.10 (protocol#12).
fn hash_to_point(input: &[u8]) -> RistrettoPoint {
    let mut tagged = Vec::with_capacity(OPRF_HASH_DST.len() + 1 + input.len());
    tagged.extend_from_slice(OPRF_HASH_DST.as_bytes());
    tagged.push(0x1f);
    tagged.extend_from_slice(input);
    RistrettoPoint::from_uniform_bytes(&sha512_64(&tagged))
}

/// Computes a SHA-512 digest with the audited [`sha2`] crate.
fn sha512_64(data: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Derives a 32-byte match token via HKDF-SHA256 over the unblinded element.
///
/// Uses the audited [`hkdf`] crate: extract with the group-ratchet label as
/// salt, then expand over `OPRF_TOKEN_INFO || 0x1f || element || 0x1f ||
/// input`, binding the token to the transcript element and the identifier.
fn hkdf_token(unblinded_element: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut info = Vec::with_capacity(OPRF_TOKEN_INFO.len() + 1 + 32 + 1 + input.len());
    info.extend_from_slice(OPRF_TOKEN_INFO.as_bytes());
    info.push(0x1f);
    info.extend_from_slice(unblinded_element);
    info.push(0x1f);
    info.extend_from_slice(input);
    let hk = Hkdf::<sha2::Sha256>::new(Some(GROUP_RATCHET_KDF_INFO.as_bytes()), unblinded_element);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("32-byte HKDF-SHA256 expand must succeed");
    out
}

/// Draws a fresh nonzero scalar from `OsRng`.
///
/// Uses `from_bytes_mod_order_wide` over 64 random bytes instead of
/// `Scalar::random`, which needs curve25519-dalek's `rand_core` feature
/// (extra dependency surface this crate deliberately avoids).
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
    if scalar == Scalar::ZERO {
        Scalar::from(1u8)
    } else {
        scalar
    }
}

/// Reduces 32 secret bytes to the server scalar.
fn scalar_from_bytes(secret: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*secret)
}

/// Parses a compressed wire element or rejects it as non-canonical.
fn parse_point(raw: &[u8; 32]) -> Result<RistrettoPoint, OprfError> {
    CompressedRistretto::from_slice(raw)
        .map_err(|_| OprfError::InvalidElement)?
        .decompress()
        .ok_or(OprfError::InvalidElement)
}

/// Builds the DLEQ challenge scalar over the proof transcript.
fn proof_challenge(
    server_public: &RistrettoPoint,
    blinded: &RistrettoPoint,
    evaluated: &RistrettoPoint,
    commitment_g: &RistrettoPoint,
    commitment_b: &RistrettoPoint,
) -> Scalar {
    let mut transcript = Vec::with_capacity(OPRF_PROOF_DST.len() + 1 + 5 * 32);
    transcript.extend_from_slice(OPRF_PROOF_DST.as_bytes());
    transcript.push(0x1f);
    for point in [
        server_public,
        blinded,
        evaluated,
        commitment_g,
        commitment_b,
    ] {
        transcript.extend_from_slice(&point.compress().to_bytes());
    }
    Scalar::from_bytes_mod_order_wide(&sha512_64(&transcript))
}

/// Blinds an input with a fresh nonzero random scalar.
///
/// Returns the compressed blinded element and the blind scalar (wire bytes).
pub fn oprf_blind(input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let blind = random_scalar();
    let blinded = hash_to_point(input) * blind;
    (blinded.compress().to_bytes(), blind.to_bytes())
}

/// Applies the server static key and attaches a DLEQ proof of correctness.
pub fn oprf_evaluate(
    blinded: &[u8; 32],
    server_secret: &[u8; 32],
) -> Result<OprfEvaluation, OprfError> {
    let blinded_point = parse_point(blinded)?;
    let server_scalar = scalar_from_bytes(server_secret);
    let evaluated = blinded_point * server_scalar;
    let nonce = random_scalar();
    let commitment_g = RistrettoPoint::mul_base(&nonce);
    let commitment_b = blinded_point * nonce;
    let server_public = RistrettoPoint::mul_base(&server_scalar);
    let challenge = proof_challenge(
        &server_public,
        &blinded_point,
        &evaluated,
        &commitment_g,
        &commitment_b,
    );
    let response = nonce - challenge * server_scalar;
    Ok(OprfEvaluation {
        evaluated: evaluated.compress().to_bytes(),
        proof_challenge: challenge.to_bytes(),
        proof_response: response.to_bytes(),
    })
}

/// Returns the server OPRF public key `K = k * G` as compressed bytes.
pub fn oprf_server_public_key(server_secret: &[u8; 32]) -> [u8; 32] {
    RistrettoPoint::mul_base(&scalar_from_bytes(server_secret))
        .compress()
        .to_bytes()
}

/// Unblinds an evaluation, verifies the DLEQ proof, and derives the token.
///
/// Returns the unblinded element plus the HKDF-SHA256 match token bound to
/// the input and the transcript. Any substituted element or proof fails
/// with [`OprfError::VerificationFailed`].
pub fn oprf_unblind_and_token(
    evaluation: &OprfEvaluation,
    blind: &[u8; 32],
    server_public: &[u8; 32],
    input: &[u8],
) -> Result<([u8; 32], [u8; 32]), OprfError> {
    let blind_scalar = Scalar::from_canonical_bytes(*blind)
        .into_option()
        .ok_or(OprfError::InvalidElement)?;
    if blind_scalar == Scalar::ZERO {
        return Err(OprfError::InvalidElement);
    }
    let blinded_point = hash_to_point(input) * blind_scalar;
    let evaluated_point = parse_point(&evaluation.evaluated)?;
    let server_point = parse_point(server_public)?;
    let challenge = Scalar::from_canonical_bytes(evaluation.proof_challenge)
        .into_option()
        .ok_or(OprfError::InvalidElement)?;
    let response = Scalar::from_canonical_bytes(evaluation.proof_response)
        .into_option()
        .ok_or(OprfError::InvalidElement)?;

    let commitment_g = RistrettoPoint::mul_base(&response) + server_point * challenge;
    let commitment_b = blinded_point * response + evaluated_point * challenge;
    let expected = proof_challenge(
        &server_point,
        &blinded_point,
        &evaluated_point,
        &commitment_g,
        &commitment_b,
    );
    if expected != challenge {
        return Err(OprfError::VerificationFailed);
    }

    let unblinded = evaluated_point * blind_scalar.invert();
    let token = hkdf_token(&unblinded.compress().to_bytes(), input);
    Ok((unblinded.compress().to_bytes(), token))
}

/// Finalizes the deterministic directory token for a registered identifier.
///
/// Runs blind-evaluate-unblind with fresh randomness and returns the token
/// an honest client derives for the same input and server key. Intended for
/// tests and audited server-side directory commitment generation.
pub fn oprf_client_finalize(input: &[u8], server_secret: &[u8; 32]) -> Vec<u8> {
    let unblinded = hash_to_point(input) * scalar_from_bytes(server_secret);
    hkdf_token(&unblinded.compress().to_bytes(), input).to_vec()
}
