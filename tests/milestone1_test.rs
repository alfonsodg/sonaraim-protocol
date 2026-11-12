//! TDD integration tests for Milestone 1 & 5 protocol primitives:
//! - Issue #2: Ed25519 JCS card signing/verification & Sealed Sender AEAD
//! - Issue #3: Deterministic binary wire codec for envelopes and cards
//! - Issue #4: MLS group epoch ratcheting & PSI blinded contact discovery

use sonaraim_protocol::card::{CardComponent, ComponentType, MerchantSignature, SonaraimCard};
use sonaraim_protocol::crypto::{derive_public_key, sign_card_jcs, verify_card_jcs, CryptoError};
use sonaraim_protocol::envelope::{open_envelope, seal_envelope};
use sonaraim_protocol::mls_group::MlsGroupState;
use sonaraim_protocol::psi::{blind_contact_identifier, evaluate_blinded_set, match_psi_results};
use sonaraim_protocol::wire::{
    decode_card, decode_envelope, encode_card, encode_envelope, WireError,
};

fn sample_unsigned_card() -> SonaraimCard {
    SonaraimCard {
        card_id: "ord-2026-9901".to_string(),
        title: "Flight Boarding Pass".to_string(),
        summary: "Gate B12 opens at 16:30".to_string(),
        components: vec![
            CardComponent {
                component_type: ComponentType::TextBlock,
                label: "Passenger: Ana Torres".to_string(),
                value: Some("Seat 14A".to_string()),
                action_uri: None,
            },
            CardComponent {
                component_type: ComponentType::ActionButton,
                label: "Check-in".to_string(),
                value: None,
                action_uri: Some("sonaraim://checkin/9901".to_string()),
            },
        ],
        merchant_signature: MerchantSignature {
            did: "did:web:air.example.com".to_string(),
            algorithm: "Ed25519".to_string(),
            signature_hex: "00".repeat(64),
        },
    }
}

#[test]
fn signs_and_verifies_card_with_jcs_and_rejects_tampering() {
    let secret = [0x42u8; 32];
    let public = derive_public_key(&secret);
    let mut card = sample_unsigned_card();

    sign_card_jcs(&mut card, &secret).expect("signing must succeed");
    assert_eq!(verify_card_jcs(&card, &public), Ok(()));

    card.title = "Tampered Boarding Pass".to_string();
    assert_eq!(
        verify_card_jcs(&card, &public),
        Err(CryptoError::InvalidSignature)
    );
}

#[test]
fn seals_and_opens_envelope_with_aead_authentication() {
    let mailbox_secret = [0x19u8; 32];
    let mailbox_pub = derive_public_key(&mailbox_secret);
    let plaintext = b"{\"msg\":\"hello mls\"}";

    let envelope = seal_envelope("mbx_user_0001", &mailbox_pub, plaintext, 3600)
        .expect("sealing must succeed");
    let decrypted = open_envelope(&envelope, &mailbox_secret).expect("unsealing must succeed");
    assert_eq!(decrypted, plaintext);

    let mut tampered = envelope;
    tampered.mls_ciphertext[5] ^= 0xFF;
    assert_eq!(
        open_envelope(&tampered, &mailbox_secret),
        Err(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn encodes_and_decodes_wire_frames_and_rejects_truncated_input() {
    let secret = [0x33u8; 32];
    let mut card = sample_unsigned_card();
    sign_card_jcs(&mut card, &secret).expect("signing must succeed");

    let card_bytes = encode_card(&card).expect("card encoding must succeed");
    let decoded_card = decode_card(&card_bytes).expect("card decoding must succeed");
    assert_eq!(decoded_card, card);

    let mailbox_pub = derive_public_key(&[0x55u8; 32]);
    let env = seal_envelope(
        "mbx_wire_0001",
        &mailbox_pub,
        b"payload-frame-bytes-012345",
        600,
    )
    .expect("seal must succeed");
    let env_bytes = encode_envelope(&env).expect("envelope encoding must succeed");
    let decoded_env = decode_envelope(&env_bytes).expect("envelope decoding must succeed");
    assert_eq!(decoded_env, env);

    assert_eq!(
        decode_envelope(&env_bytes[..4]),
        Err(WireError::TruncatedFrame)
    );
}

#[test]
fn rotates_mls_group_epoch_keys_and_excludes_removed_members() {
    let mut group = MlsGroupState::new("grp-alpha-1", "did:sonaraim:alice");
    let epoch0_key = group.current_epoch_key();

    group.add_member("did:sonaraim:bob").expect("add bob");
    let epoch1_key = group.current_epoch_key();
    assert_ne!(epoch0_key, epoch1_key);
    assert_eq!(group.epoch(), 1);
    assert!(group.is_member("did:sonaraim:bob"));

    let msg_epoch1 = group
        .encrypt_application_msg(b"secret-for-bob")
        .expect("encrypt");
    assert_eq!(
        group.decrypt_application_msg(&msg_epoch1, 1, "did:sonaraim:bob"),
        Ok(b"secret-for-bob".to_vec())
    );

    group.remove_member("did:sonaraim:bob").expect("remove bob");
    let msg_epoch2 = group
        .encrypt_application_msg(b"post-removal")
        .expect("encrypt");
    assert_eq!(group.epoch(), 2);
    assert!(group
        .decrypt_application_msg(&msg_epoch2, 2, "did:sonaraim:bob")
        .is_err());
}

#[test]
fn discovers_shared_contacts_via_psi_without_exposing_non_matches() {
    let server_secret = [0x7Au8; 32];
    let registered_phones = vec!["+51999888777", "+14155550101"];
    let client_phones = vec!["+51999888777", "+51911222333"];
    let client_blinds: Vec<Vec<u8>> = client_phones
        .iter()
        .map(|p| blind_contact_identifier(p, b"salt-1"))
        .collect();

    let server_eval = evaluate_blinded_set(&client_blinds, &registered_phones, &server_secret);
    let matches = match_psi_results(&client_phones, &server_eval, b"salt-1", &server_secret);

    assert_eq!(matches, vec!["+51999888777".to_string()]);
}
