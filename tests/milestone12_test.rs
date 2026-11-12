//! Milestone 12 TDD test suite for `sonaraim-protocol` (Issues #6 and #7).
//!
//! Verifies `KeyRing` key rotation, key-expiration enforcement, and revoked-key
//! rejection (#6), as well as MLS post-compromise emergency ratchet and
//! deterministic SHA-256 transcript digest (#7).

use sonaraim_protocol::card::{CardComponent, ComponentType, MerchantSignature, SonaraimCard};
use sonaraim_protocol::keyring::{KeyEntry, KeyRing, KeyRingError};
use sonaraim_protocol::mls_group::{MlsError, MlsGroupState};

fn sample_card() -> SonaraimCard {
    SonaraimCard {
        card_id: "card-m12-001".to_string(),
        title: "Security Alert".to_string(),
        summary: "Rotated key verification test card.".to_string(),
        components: vec![CardComponent {
            component_type: ComponentType::TextBlock,
            label: "Verified with versioned key ring".to_string(),
            value: None,
            action_uri: None,
        }],
        merchant_signature: MerchantSignature {
            did: "did:sonaraim:merchant-m12".to_string(),
            algorithm: "Ed25519".to_string(),
            signature_hex: String::new(),
        },
    }
}

#[test]
fn keyring_rotates_active_keys_and_verifies_historical_signatures() {
    let mut ring = KeyRing::new();
    ring.add_key(KeyEntry {
        kid: "kid-2026-q1".to_string(),
        key_bytes: [0x11u8; 32],
        not_before_ms: 1_000,
        expires_at_ms: 5_000,
        revoked: false,
    })
    .ok();
    ring.add_key(KeyEntry {
        kid: "kid-2026-q2".to_string(),
        key_bytes: [0x22u8; 32],
        not_before_ms: 3_000,
        expires_at_ms: 9_000,
        revoked: false,
    })
    .ok();

    assert_eq!(ring.set_active_key("kid-2026-q1"), Ok(()));
    assert_eq!(ring.active_key_id(), Some("kid-2026-q1"));

    let mut card_q1 = sample_card();
    let signed_kid_1 = ring.sign_card_with_active_key(&mut card_q1, 2_000);
    assert_eq!(signed_kid_1, Ok("kid-2026-q1".to_string()));
    let sig_q1 = card_q1.merchant_signature.signature_hex.clone();

    // Rotate active key to Q2
    assert_eq!(ring.set_active_key("kid-2026-q2"), Ok(()));
    let mut card_q2 = sample_card();
    let signed_kid_2 = ring.sign_card_with_active_key(&mut card_q2, 4_000);
    assert_eq!(signed_kid_2, Ok("kid-2026-q2".to_string()));
    let sig_q2 = card_q2.merchant_signature.signature_hex.clone();

    // Both Q1 (historical, still within 1_000..=5_000) and Q2 verify at t=4_000
    assert_eq!(
        ring.verify_card_with_kid(&card_q1, "kid-2026-q1", &sig_q1, 4_000),
        Ok(())
    );
    assert_eq!(
        ring.verify_card_with_kid(&card_q2, "kid-2026-q2", &sig_q2, 4_000),
        Ok(())
    );
}

#[test]
fn keyring_rejects_unknown_expired_not_yet_valid_and_revoked_keys() {
    let mut ring = KeyRing::new();
    ring.add_key(KeyEntry {
        kid: "kid-temp".to_string(),
        key_bytes: [0x33u8; 32],
        not_before_ms: 10_000,
        expires_at_ms: 20_000,
        revoked: false,
    })
    .ok();
    ring.set_active_key("kid-temp").ok();

    let mut card = sample_card();
    assert_eq!(
        ring.sign_card_with_active_key(&mut card, 15_000),
        Ok("kid-temp".to_string())
    );
    let sig = card.merchant_signature.signature_hex.clone();

    // Unknown key ID
    assert_eq!(
        ring.verify_card_with_kid(&card, "kid-missing", &sig, 15_000),
        Err(KeyRingError::UnknownKeyId("kid-missing".to_string()))
    );

    // Not yet valid (now_ms < not_before_ms)
    assert_eq!(
        ring.verify_card_with_kid(&card, "kid-temp", &sig, 9_999),
        Err(KeyRingError::KeyExpired {
            kid: "kid-temp".to_string(),
            now_ms: 9_999,
            not_before_ms: 10_000,
            expires_at_ms: 20_000,
        })
    );

    // Expired (now_ms > expires_at_ms)
    assert_eq!(
        ring.verify_card_with_kid(&card, "kid-temp", &sig, 20_001),
        Err(KeyRingError::KeyExpired {
            kid: "kid-temp".to_string(),
            now_ms: 20_001,
            not_before_ms: 10_000,
            expires_at_ms: 20_000,
        })
    );

    // Revoked key
    assert_eq!(ring.revoke_key("kid-temp"), Ok(()));
    assert_eq!(
        ring.verify_card_with_kid(&card, "kid-temp", &sig, 15_000),
        Err(KeyRingError::KeyRevoked("kid-temp".to_string()))
    );
    assert_eq!(
        ring.sign_card_with_active_key(&mut card, 15_000),
        Err(KeyRingError::KeyRevoked("kid-temp".to_string()))
    );
}

#[test]
fn mls_force_recovery_ratchet_purges_compromised_epochs_and_tracks_transcript() {
    let mut group_a = MlsGroupState::new("grp-enterprise-01", "did:sonaraim:alice");
    let mut group_b = MlsGroupState::new("grp-enterprise-01", "did:sonaraim:alice");
    assert_eq!(
        group_a.transcript_digest_hex(),
        group_b.transcript_digest_hex()
    );
    let digest_epoch_0 = group_a.transcript_digest_hex();

    assert_eq!(group_a.add_member("did:sonaraim:bob"), Ok(1));
    assert_eq!(group_b.add_member("did:sonaraim:bob"), Ok(1));
    assert_ne!(group_a.transcript_digest_hex(), digest_epoch_0);
    assert_eq!(
        group_a.transcript_digest_hex(),
        group_b.transcript_digest_hex()
    );

    let msg_epoch_1 = group_a
        .encrypt_application_msg(b"confidential-before-compromise")
        .unwrap_or_default();

    // Non-purging recovery ratchet advances to epoch 2 while keeping epoch 1 accessible
    let entropy_1 = b"fresh-csprng-entropy-block-01";
    assert_eq!(group_a.force_recovery_ratchet(entropy_1, false), Ok(2));
    assert_eq!(group_b.force_recovery_ratchet(entropy_1, false), Ok(2));
    assert_eq!(
        group_a.transcript_digest_hex(),
        group_b.transcript_digest_hex()
    );
    assert!(group_a
        .decrypt_application_msg(&msg_epoch_1, 1, "did:sonaraim:bob")
        .is_ok());

    // Emergency purging recovery ratchet advances to epoch 3 and purges epochs 0..=2
    let entropy_2 = b"emergency-post-compromise-seed-02";
    assert_eq!(group_a.force_recovery_ratchet(entropy_2, true), Ok(3));
    assert_eq!(group_b.force_recovery_ratchet(entropy_2, true), Ok(3));
    assert_eq!(
        group_a.transcript_digest_hex(),
        group_b.transcript_digest_hex()
    );
    assert_eq!(group_a.current_epoch_key(), group_b.current_epoch_key());

    // Purged epoch 1 must now return UnknownEpoch(1)
    assert_eq!(
        group_a.decrypt_application_msg(&msg_epoch_1, 1, "did:sonaraim:bob"),
        Err(MlsError::UnknownEpoch(1))
    );

    // Current epoch 3 encrypts and decrypts cleanly
    let msg_epoch_3 = group_a
        .encrypt_application_msg(b"post-recovery-payload")
        .unwrap_or_default();
    assert_eq!(
        group_b.decrypt_application_msg(&msg_epoch_3, 3, "did:sonaraim:bob"),
        Ok(b"post-recovery-payload".to_vec())
    );
}
