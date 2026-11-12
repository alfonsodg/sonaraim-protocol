//! Comprehensive unit and integration tests for `sonaraim-protocol`.
//!
//! Verifies valid Sonaraim Cards, rejection of raw HTML/script XSS payloads,
//! DID format verification (`did:web:` / `did:sonaraim:` + `Ed25519`), and
//! `SealedEnvelope` cryptographic and routing bounds.

use sonaraim_protocol::card::{
    validate_card, CardComponent, CardValidationError, ComponentType, MerchantSignature,
    SonaraimCard,
};
use sonaraim_protocol::envelope::{
    validate_envelope, EnvelopeValidationError, SealedEnvelope, MAX_CIPHERTEXT_LEN,
};

/// Builds a valid baseline [`SonaraimCard`] for testing mutations.
fn sample_valid_card() -> SonaraimCard {
    SonaraimCard {
        card_id: "card-order-2026-0001".to_string(),
        title: "Order Confirmation #2026".to_string(),
        summary: "Your hardware security key shipment has been dispatched.".to_string(),
        components: vec![
            CardComponent {
                component_type: ComponentType::TextBlock,
                label: "Estimated delivery: Tomorrow by 18:00 UTC".to_string(),
                value: None,
                action_uri: None,
            },
            CardComponent {
                component_type: ComponentType::KeyValueRow,
                label: "Tracking ID".to_string(),
                value: Some("SNR-99887766".to_string()),
                action_uri: None,
            },
            CardComponent {
                component_type: ComponentType::ActionButton,
                label: "Track Package".to_string(),
                value: None,
                action_uri: Some("https://merchant.example.com/track/SNR-99887766".to_string()),
            },
        ],
        merchant_signature: MerchantSignature {
            did: "did:web:merchant.example.com".to_string(),
            algorithm: "Ed25519".to_string(),
            signature_hex: "a1b2c3d4".repeat(16),
        },
    }
}

/// Builds a valid baseline [`SealedEnvelope`] for testing mutations.
fn sample_valid_envelope() -> SealedEnvelope {
    SealedEnvelope {
        mailbox_id: "mbx_9f8e7d6c5b4a3210".to_string(),
        ephemeral_pub_key: vec![0x42; 32],
        mls_ciphertext: vec![0x99; 128],
        ttl_seconds: 86_400,
    }
}

#[test]
fn accepts_valid_card_with_did_web_and_did_sonaraim() {
    let mut card = sample_valid_card();
    assert_eq!(validate_card(&card), Ok(()));

    card.merchant_signature.did = "did:sonaraim:merchant-node-01".to_string();
    card.components.push(CardComponent {
        component_type: ComponentType::from_wire_str("media_image"),
        label: "Product preview".to_string(),
        value: None,
        action_uri: Some("sonaraim://asset/preview-01".to_string()),
    });
    assert_eq!(validate_card(&card), Ok(()));
}

#[test]
fn rejects_unsupported_raw_html_and_script_component_types() {
    let mut card = sample_valid_card();
    card.components.push(CardComponent {
        component_type: ComponentType::from_wire_str("raw_html"),
        label: "Fallback text".to_string(),
        value: None,
        action_uri: None,
    });
    assert_eq!(
        validate_card(&card),
        Err(CardValidationError::UnsupportedComponentType(
            "raw_html".to_string()
        ))
    );
}

#[test]
fn rejects_xss_markup_and_javascript_action_uris() {
    let mut card = sample_valid_card();
    card.title = "<script>alert('xss')</script>".to_string();
    assert_eq!(
        validate_card(&card),
        Err(CardValidationError::UnsafeMarkupDetected("card_metadata"))
    );

    let mut card_label_xss = sample_valid_card();
    card_label_xss.components[0].label = "Click <img src=x onerror=alert(1)>".to_string();
    assert_eq!(
        validate_card(&card_label_xss),
        Err(CardValidationError::UnsafeMarkupDetected("component.label"))
    );

    let mut card_js_uri = sample_valid_card();
    card_js_uri.components[2].action_uri = Some("javascript:alert(document.cookie)".to_string());
    assert!(matches!(
        validate_card(&card_js_uri),
        Err(CardValidationError::InvalidActionUri(_))
    ));
}

#[test]
fn rejects_invalid_did_methods_algorithms_and_signatures() {
    let mut card = sample_valid_card();
    card.merchant_signature.did =
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string();
    assert!(matches!(
        validate_card(&card),
        Err(CardValidationError::InvalidMerchantDid(_))
    ));

    let mut card_bad_alg = sample_valid_card();
    card_bad_alg.merchant_signature.algorithm = "none".to_string();
    assert_eq!(
        validate_card(&card_bad_alg),
        Err(CardValidationError::UnsupportedSignatureAlgorithm(
            "none".to_string()
        ))
    );

    let mut card_bad_sig = sample_valid_card();
    card_bad_sig.merchant_signature.signature_hex = "deadbeef".to_string();
    assert_eq!(
        validate_card(&card_bad_sig),
        Err(CardValidationError::InvalidSignatureHex)
    );
}

#[test]
fn validates_sealed_envelope_constraints() {
    let env = sample_valid_envelope();
    assert_eq!(validate_envelope(&env), Ok(()));

    let mut bad_mbx = sample_valid_envelope();
    bad_mbx.mailbox_id = "short".to_string();
    assert!(matches!(
        validate_envelope(&bad_mbx),
        Err(EnvelopeValidationError::InvalidMailboxId(_))
    ));

    let mut zero_key = sample_valid_envelope();
    zero_key.ephemeral_pub_key = vec![0u8; 32];
    assert_eq!(
        validate_envelope(&zero_key),
        Err(EnvelopeValidationError::InvalidEphemeralPublicKey(32))
    );

    let mut oversized_ct = sample_valid_envelope();
    oversized_ct.mls_ciphertext = vec![0x11; MAX_CIPHERTEXT_LEN + 1];
    assert_eq!(
        validate_envelope(&oversized_ct),
        Err(EnvelopeValidationError::InvalidCiphertextSize(
            MAX_CIPHERTEXT_LEN + 1
        ))
    );

    let mut expired_ttl = sample_valid_envelope();
    expired_ttl.ttl_seconds = 10;
    assert_eq!(
        validate_envelope(&expired_ttl),
        Err(EnvelopeValidationError::InvalidTtlSeconds(10))
    );
}
