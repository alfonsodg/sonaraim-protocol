//! JCS string-escaping contract tests (Issue #2 scope, RFC 8785 §3).
//!
//! `canonical_card_bytes` must escape `"`, `\`, and C0 control characters so
//! the signed preimage is valid canonical JSON for adversarial-but-legal card
//! fields (quotes and backslashes pass `validate_card`).

use sonaraim_protocol::card::{CardComponent, ComponentType, MerchantSignature, SonaraimCard};
use sonaraim_protocol::crypto::{
    canonical_card_bytes, ed25519_public_key_bytes, sign_card_jcs, verify_card_jcs,
};

fn escape_card() -> SonaraimCard {
    SonaraimCard {
        card_id: "card-escape-001".to_string(),
        title: "A \"quoted\" title".to_string(),
        summary: "line1\nline2".to_string(),
        components: vec![CardComponent {
            component_type: ComponentType::TextBlock,
            label: "back\\slash".to_string(),
            value: None,
            action_uri: None,
        }],
        merchant_signature: MerchantSignature {
            did: "did:web:escape.example.com".to_string(),
            algorithm: "Ed25519".to_string(),
            signature_hex: "00".repeat(64),
        },
    }
}

#[test]
fn jcs_canonical_bytes_escape_quotes_backslashes_and_controls() {
    let card = escape_card();
    let canonical = String::from_utf8(canonical_card_bytes(&card)).expect("canonical JCS is UTF-8");

    let expected = concat!(
        "{\"card_id\":\"card-escape-001\",",
        "\"components\":[{\"action_uri\":\"\",\"label\":\"back\\\\slash\",",
        "\"type\":\"text_block\",\"value\":\"\"}],",
        "\"did\":\"did:web:escape.example.com\",",
        "\"summary\":\"line1\\nline2\",",
        "\"title\":\"A \\\"quoted\\\" title\"}",
    );
    assert_eq!(canonical, expected);
}

#[test]
fn jcs_escaped_card_signs_and_verifies_with_tamper_rejection() {
    let secret = [0x9eu8; 32];
    let public = ed25519_public_key_bytes(&secret);
    let mut card = escape_card();

    sign_card_jcs(&mut card, &secret).expect("signing must succeed");
    assert_eq!(verify_card_jcs(&card, &public), Ok(()));

    card.summary = "line1\nline2 tampered".to_string();
    assert!(verify_card_jcs(&card, &public).is_err());
}
