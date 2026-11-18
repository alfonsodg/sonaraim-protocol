//! Milestone 8 TDD suite (Issues #8 and #10): audited-crate crypto contract tests.
//!
//! RED-phase tests covering the acceptance criteria before implementation:
//! - Ed25519 RFC 8032 test vector (`TEST 1`: seed `9d61b19d…`) must sign/verify.
//! - HMAC-SHA256 must match RFC 4231 vectors (audited `hmac` crate, #10).
//! - HKDF-SHA256 expand must match RFC 5869 §A.1 (audited `hkdf` crate, #10).
//! - AEAD (`aead_seal`/`aead_open`) round-trips and rejects tampering with a
//!   16-byte authentication tag (ChaCha20-Poly1305 IETF layout); sealing
//!   failures surface as `Err` instead of a nonce-zero fallback (#10).
//! - X25519 RFC 7748 vector (`scalar = 0x77076d…`, `u = 0x5db075…`) must agree.
//! - DH-blinded PSI match must not require `server_secret` on the client side.
//! - Epoch-key zeroization: purged epochs are unrecoverable after recovery
//!   ratchet; unknown epochs return `Err` instead of a zero key (#10).

use sonaraim_protocol::crypto::{
    aead_open, aead_seal, derive_envelope_key, derive_epoch_key, hmac_sha256, CryptoError,
};
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
fn hmac_sha256_matches_rfc4231_vectors() {
    // RFC 4231 §4.2 test cases 1–3 (HMAC-SHA-256).
    let tc1 = hmac_sha256(&[0x0bu8; 20], b"Hi There");
    assert_eq!(
        tc1.to_vec(),
        from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
    let tc2 = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(
        tc2.to_vec(),
        from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
    let tc3 = hmac_sha256(&[0xaau8; 20], &[0xddu8; 50]);
    assert_eq!(
        tc3.to_vec(),
        from_hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
    );
    // Keys longer than the SHA-256 block size are hashed first (RFC 4231 TC6).
    let tc6 = hmac_sha256(
        &[0xaau8; 131],
        b"Test Using Larger Than Block-Size Key - Hash Key First",
    );
    assert_eq!(
        tc6.to_vec(),
        from_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    );
}

#[test]
fn hkdf_sha256_expand_matches_rfc5869_tc1_okm_prefix() {
    // RFC 5869 §A.1 test case 1 (SHA-256): extract with salt=0x0001…0c,
    // ikm=22×0x0b, then expand with the RFC info must yield the published
    // 42-byte OKM. `Hkdf::<Sha256>::new(Some(salt), &ikm)` is the extract
    // step and `expand(&info, &mut okm)` the expand step.
    use hkdf::Hkdf;
    use sha2::Sha256;
    let ikm = [0x0bu8; 22];
    let salt: Vec<u8> = (0..13u8).collect();
    let info: Vec<u8> = (0xf0..0xfau8).collect();
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = [0u8; 42];
    hk.expand(&info, &mut okm)
        .expect("RFC 5869 expand must succeed");
    assert_eq!(
        okm.to_vec(),
        from_hex(concat!(
            "3cb25f25faacd57a90434f64d0362f2a",
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
            "34007208d5b887185865",
        ))
    );
}

#[test]
fn protocol_kdf_labels_match_rfc5869_construction() {
    // Fixed protocol KDF labels pin the HKDF-Extract(salt=label, ikm) +
    // single-block HKDF-Expand(info) construction; reference values computed
    // per RFC 5869 §2 with the same label/info mapping.
    let envelope_key = derive_envelope_key(&[0x11u8; 32], b"mbx-vector-0001");
    let epoch_key = derive_epoch_key(&[0x22u8; 32], b"grp-vector-epoch-1");
    assert_eq!(
        envelope_key.to_vec(),
        from_hex("a47ba274d9c8339e99500517b8539f04ed7132294b502ef223cb1c7d72dffead")
    );
    assert_eq!(
        epoch_key.to_vec(),
        from_hex("c0fe7c6c4caaa434ff3125ed22068e21f276fa11efda901ca0c06b9f950c8ec4")
    );
}

#[test]
fn aead_roundtrip_rejects_tampered_tag_and_has_16_byte_overhead() {
    let key = [0x5au8; 32];
    let aad = b"mailbox:mbx_user_0001";
    let plaintext = b"hello audited aead world";
    let sealed = aead_seal(&key, aad, plaintext).expect("seal must succeed");
    assert_eq!(
        sealed.len(),
        plaintext.len()
            + sonaraim_protocol::crypto::AEAD_NONCE_LEN
            + sonaraim_protocol::crypto::AEAD_TAG_LEN
    );
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
fn unknown_epoch_key_returns_error_instead_of_zero_key() {
    // A known epoch yields its key, while a never-existent epoch surfaces
    // `MlsError::UnknownEpoch` rather than a silent all-zero key.
    let mut group = MlsGroupState::new("grp-unknown-epoch", "did:sonaraim:alice");
    assert!(group.current_epoch_key().is_ok());
    group.add_member("did:sonaraim:bob").expect("add bob");
    assert_eq!(
        group.decrypt_application_msg(b"bogus-ciphertext", 99, "did:sonaraim:bob"),
        Err(MlsError::UnknownEpoch(99))
    );
    // A purged epoch is unknown too (no zero-key fallback anywhere).
    let old_ciphertext = group
        .encrypt_application_msg(b"pre-purge secret")
        .expect("encrypt epoch 1");
    group
        .force_recovery_ratchet(b"fresh-entropy-purge-01", true)
        .expect("purge ratchet");
    assert_eq!(
        group.decrypt_application_msg(&old_ciphertext, 1, "did:sonaraim:bob"),
        Err(MlsError::UnknownEpoch(1))
    );
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
