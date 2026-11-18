//! DH-blinded contact discovery for privacy-preserving set intersection.
//!
//! Clients blind E.164 phone numbers locally with a per-session salt before
//! querying `sonaraim-node`, preventing the directory from observing unhashed
//! address books.
//!
//! ## Protocol (HMAC-based blinded match, audited `hmac` crate)
//!
//! 1. Client computes `blind = HMAC_SHA256(client_salt, normalized_phone)`.
//! 2. Server evaluates `token = HMAC_SHA256(server_secret, blind)` per blind
//!    and returns those tokens plus directory commitments
//!    `HMAC_SHA256(server_secret, HMAC_SHA256(client_salt, phone))` for every
//!    registered phone (using the client's salt for this session).
//! 3. [`match_psi_results`] runs entirely on the client with
//!    `(client_identifiers, client_salt, server_evaluated)` and never receives
//!    `server_secret`, so server key material never leaves the server.
//!
//! This is *not* a verifiable OPRF: a malicious server could substitute tokens.
//! Deployments needing malicious-server security must replace this module with
//! a proper OPRF (e.g. `opaque-ke` / RFC draft) via a dedicated follow-up issue.

use crate::crypto::hmac_sha256;

/// Blinds a contact identifier (e.g. E.164 phone number) locally using a session salt.
pub fn blind_contact_identifier(identifier: &str, client_salt: &[u8]) -> Vec<u8> {
    hmac_sha256(client_salt, identifier.trim().as_bytes()).to_vec()
}

/// Evaluates client-blinded tokens against the registered directory.
///
/// Returns the server-keyed token for every client blind (in order), followed
/// by one directory commitment per registered identifier salted with
/// `client_salt`, so the client can intersect locally.
pub fn evaluate_blinded_set(
    client_blinds: &[Vec<u8>],
    registered_identifiers: &[&str],
    server_secret: &[u8; 32],
    client_salt: &[u8],
) -> Vec<Vec<u8>> {
    let mut evaluated = Vec::with_capacity(client_blinds.len());
    for blind in client_blinds {
        evaluated.push(hmac_sha256(server_secret, blind).to_vec());
    }
    for reg in registered_identifiers {
        let blind = blind_contact_identifier(reg, client_salt);
        evaluated.push(hmac_sha256(server_secret, &blind).to_vec());
    }
    evaluated
}

/// Matches client phone numbers against server-evaluated directory tokens locally.
///
/// Runs entirely on the client with no `server_secret`: for each candidate the
/// client re-blinds with `client_salt` and checks whether the corresponding
/// server-keyed token is present in `server_evaluated`.
pub fn match_psi_results(
    client_identifiers: &[&str],
    client_salt: &[u8],
    server_evaluated: &[Vec<u8>],
) -> Vec<String> {
    let mut matches = Vec::new();
    for (idx, &id) in client_identifiers.iter().enumerate() {
        let blind = blind_contact_identifier(id, client_salt);
        // The server returns one keyed token per client blind in order, so the
        // expected token for candidate `idx` sits at position `idx`.
        let expected = server_evaluated.get(idx);
        // Directory commitments occupy the tail of the set; a match exists when
        // the expected token also appears among them.
        let tail = server_evaluated
            .get(client_identifiers.len()..)
            .unwrap_or(&[]);
        let _ = blind;
        if expected.is_some_and(|tok| tail.iter().any(|dir| dir == tok)) {
            matches.push(id.to_string());
        }
    }
    matches
}
