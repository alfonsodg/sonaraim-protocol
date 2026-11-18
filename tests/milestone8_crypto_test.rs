//! Milestone 8 TDD suite (Issue #8): audited-crate crypto contract tests.
//!
//! RED-phase tests covering the acceptance criteria before implementation:
//! - Ed25519 RFC 8032 test vector (`TEST 1`: seed `9d61b19d…`) must sign/verify.
//! - AEAD (`aead_seal`/`aead_open`) round-trips and rejects tampering with a
//!   16-byte authentication tag (ChaCha20-Poly1305 IETF layout).
//! - X25519 RFC 7748 vector (`scalar = 0x77076d…`, `u = 0x5db075…`) must agree.
//! - DH-blinded PSI match must not require `server_secret` on the client side.
//! - Epoch-key zeroization: purged epochs are unrecoverable after recovery ratchet.

use sonaraim_protocol::crypto::{aead_open, aead_seal, CryptoError};
use sonaraim_protocol::mls_group::{MlsError, MlsGroupState};
use sonaraim_protocol::psi::{blind_contact_identifier, evaluate_blinded_set, match_psi_results};

/// Converts lowercase hex into bytes without external crates.
fn from_hex(hex: &str) -> Vec<u8> {
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut idx = 0;
    while idx + 1 < bytes.len() {
        let hi = (bytes[idx] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[idx + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    out
}

#[test]
fn ed25519_rfc8032_test1_vector_verifies() {
    // RFC 8032 §7.1 TEST 1: seed is 9d61b19d…2cc4‖4449c569…e7f60 (two lines
    // in the RFC text); public key d75a9801… and empty-message signature
    // e5564300…e7a100b.
    let secret_hex = concat!(
        "9d61b19deffd5a60ba844af492ec2cc4",
        "4449c5697b326919703bac031cae7f60",
    );
    let public_hex = concat!(
        "d75a980182b10ab7d54bfed3c964073a",
        "0ee172f3daa62325af021a68f707511a",
    );
    let signature_hex = concat!(
        "e5564300c360ac729086e2cc806e828a",
        "84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46b",
        "d25bf5f0595bbe24655141438e7a100b",
    );
    let secret = from_hex(secret_hex);
    let expected_public = from_hex(public_hex);
    let expected_signature = from_hex(signature_hex);

    let mut secret_arr = [0u8; 32];
    secret_arr.copy_from_slice(&secret);

    let derived = sonaraim_protocol::crypto::ed25519_public_key_bytes(&secret_arr);
    assert_eq!(derived.to_vec(), expected_public);

    let signature = sonaraim_protocol::crypto::ed25519_sign_bytes(&secret_arr, &[]);
    assert_eq!(signature.to_vec(), expected_signature);
}

#[test]
fn x25519_rfc7748_vector_agrees() {
    // RFC 7748 ladder vectorset1 (mirrors x25519-dalek own test vector).
    let scalar_hex = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
    let u_hex = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
    let expected_hex = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&from_hex(scalar_hex));
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&from_hex(u_hex));

    let shared = sonaraim_protocol::crypto::x25519_raw(&scalar, &peer);
    assert_eq!(shared.to_vec(), from_hex(expected_hex));
}

#[test]
fn aead_roundtrip_rejects_tampered_tag_and_has_16_byte_overhead() {
    let key = [0x5au8; 32];
    let aad = b"mailbox:mbx_user_0001";
    let plaintext = b"hello audited aead world";
    let sealed = aead_seal(&key, aad, plaintext);
    assert_eq!(
        sealed.len(),
        plaintext.len()
            + sonaraim_protocol::crypto::AEAD_NONCE_LEN
            + sonaraim_protocol::crypto::AEAD_TAG_LEN
    );
    assert_eq!(aead_open(&key, aad, &sealed), Ok(plaintext.to_vec()));

    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert_eq!(
        aead_open(&key, aad, &tampered),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn psi_match_needs_no_server_secret_on_client() {
    let registered = vec!["+51999888777", "+14155550101"];
    let client_phones = vec!["+51999888777", "+51911222333"];
    let client_salt = b"session-salt-8";
    let server_secret = [0x7au8; 32];
    let client_blinds: Vec<Vec<u8>> = client_phones
        .iter()
        .map(|p| blind_contact_identifier(p, client_salt))
        .collect();

    let server_eval =
        evaluate_blinded_set(&client_blinds, &registered, &server_secret, client_salt);
    // Client-side matching takes only directory commitments, never `server_secret`.
    let matches = match_psi_results(&client_phones, client_salt, &server_eval);
    assert_eq!(matches, vec!["+51999888777".to_string()]);
}

#[test]
fn epoch_key_zeroization_purges_compromised_history() {
    let mut group = MlsGroupState::new("grp-zeroize-01", "did:sonaraim:alice");
    group.add_member("did:sonaraim:bob").expect("add bob");
    let old_ciphertext = group
        .encrypt_application_msg(b"pre-compromise secret")
        .expect("encrypt epoch 1");
    group
        .force_recovery_ratchet(b"fresh-csprng-entropy-block-01", true)
        .expect("purge ratchet");

    assert_eq!(
        group.decrypt_application_msg(&old_ciphertext, 1, "did:sonaraim:bob"),
        Err(MlsError::UnknownEpoch(1))
    );
}
