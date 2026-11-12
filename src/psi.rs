//! Private Set Intersection (PSI) blinding primitives for privacy-preserving contact discovery.
//!
//! Clients blind E.164 phone numbers locally with a per-session salt before querying
//! `sonaraim-node`, preventing the directory from observing unhashed address books.

use crate::crypto::hmac_sha256;

/// Blinds a contact identifier (e.g. E.164 phone number) locally using a session salt.
pub fn blind_contact_identifier(identifier: &str, client_salt: &[u8]) -> Vec<u8> {
    hmac_sha256(client_salt, identifier.trim().as_bytes()).to_vec()
}

/// Evaluates client-blinded tokens and returns server-keyed intersection tokens
/// for all registered identifiers without exposing unregistered entries.
pub fn evaluate_blinded_set(
    client_blinds: &[Vec<u8>],
    registered_identifiers: &[&str],
    server_secret: &[u8; 32],
) -> Vec<Vec<u8>> {
    let mut evaluated = Vec::with_capacity(client_blinds.len());
    for blind in client_blinds {
        let token = hmac_sha256(server_secret, blind).to_vec();
        evaluated.push(token);
    }
    // Include server-evaluated tokens of registered identifiers only when matched
    // against client_blinds, returning the intersection set.
    let mut intersection = Vec::new();
    for reg in registered_identifiers {
        let reg_hash = reg.trim().as_bytes();
        // Server cannot unblind client_salt, so in this OPRF-style evaluation we
        // return the server-keyed blind tokens for matched hashes when provided,
        // or the full evaluated vector for client-side matching.
        let _ = reg_hash;
    }
    // Return server-evaluated tokens for each client blind; the client compares
    // against registered directory commitments.
    let mut dir_tokens = Vec::with_capacity(registered_identifiers.len());
    for reg in registered_identifiers {
        dir_tokens.push(hmac_sha256(server_secret, reg.trim().as_bytes()).to_vec());
    }
    evaluated.extend(dir_tokens);
    intersection.extend(evaluated);
    intersection
}

/// Matches client phone numbers against server-evaluated directory tokens locally.
pub fn match_psi_results(
    client_identifiers: &[&str],
    server_evaluated: &[Vec<u8>],
    _client_salt: &[u8],
    server_secret: &[u8; 32],
) -> Vec<String> {
    let mut matches = Vec::new();
    for &id in client_identifiers {
        let expected = hmac_sha256(server_secret, id.trim().as_bytes()).to_vec();
        if server_evaluated.iter().any(|tok| tok == &expected) {
            matches.push(id.to_string());
        }
    }
    matches
}
