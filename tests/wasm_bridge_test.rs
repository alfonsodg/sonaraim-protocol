//! WASM/TS interop tests for the Sonaraim wire codec (Issue #11).
//!
//! Pins the JSON bridge contract in `crate::wasm` so web/mobile verify the
//! same `tests/vectors/v1.json` vectors as
//! `node scripts/verify-vectors.mjs`. The wasm-pack build compiles the same
//! entry points to WebAssembly; these native tests pin the JSON shapes,
//! the wire-hex round-trip, and the typed-error behavior.

use sonaraim_protocol::crypto::{ed25519_public_key_bytes, to_hex, x25519_public_from_secret};
use sonaraim_protocol::envelope::seal_envelope;
use sonaraim_protocol::wasm_bridge::BridgeError;
use sonaraim_protocol::wasm_json::{
    canonical_card_json, decode_card_json, decode_envelope_json, encode_card_json,
    encode_envelope_json, export_vector_json, verify_card_json,
};
use sonaraim_protocol::wire::{decode_card, decode_envelope};

fn signed_card_json() -> (String, [u8; 32]) {
    let secret = [0x33u8; 32];
    let mut card = sonaraim_protocol::SonaraimCard {
        card_id: "ord-2026-9901".to_string(),
        title: "Flight Boarding Pass".to_string(),
        summary: "Gate B12 opens at 16:30".to_string(),
        components: vec![
            sonaraim_protocol::card::CardComponent {
                component_type: sonaraim_protocol::card::ComponentType::TextBlock,
                label: "Passenger: Ana Torres".to_string(),
                value: Some("Seat 14A".to_string()),
                action_uri: None,
            },
            sonaraim_protocol::card::CardComponent {
                component_type: sonaraim_protocol::card::ComponentType::ActionButton,
                label: "Check-in".to_string(),
                value: None,
                action_uri: Some("sonaraim://checkin/9901".to_string()),
            },
        ],
        merchant_signature: sonaraim_protocol::card::MerchantSignature {
            did: "did:web:air.example.com".to_string(),
            algorithm: "Ed25519".to_string(),
            signature_hex: String::new(),
        },
    };
    sonaraim_protocol::crypto::sign_card_jcs(&mut card, &secret).expect("signing must succeed");
    let public = ed25519_public_key_bytes(&secret);
    let json = format!(
        concat!(
            "{{\"card_id\":\"{}\",\"title\":\"{}\",\"summary\":\"{}\",\"components\":[",
            "{{\"type\":\"text_block\",\"label\":\"Passenger: Ana Torres\",",
            "\"value\":\"Seat 14A\",\"action_uri\":\"\"}},",
            "{{\"type\":\"action_button\",\"label\":\"Check-in\",",
            "\"value\":\"\",\"action_uri\":\"sonaraim://checkin/9901\"}}],",
            "\"did\":\"did:web:air.example.com\",\"algorithm\":\"Ed25519\",",
            "\"signature_hex\":\"{}\"}}",
        ),
        card.card_id, card.title, card.summary, card.merchant_signature.signature_hex,
    );
    (json, public)
}

fn sealed_envelope_json() -> String {
    let recipient = x25519_public_from_secret(&[0x55u8; 32]);
    let env = seal_envelope(
        "mbx_wire_0001",
        &recipient,
        b"payload-frame-bytes-012345",
        600,
    )
    .expect("seal must succeed");
    format!(
        concat!(
            "{{\"mailbox_id\":\"{}\",\"ephemeral_pub_key\":\"{}\",",
            "\"mls_ciphertext\":\"{}\",\"ttl_seconds\":{}}}",
        ),
        env.mailbox_id,
        to_hex(&env.ephemeral_pub_key),
        to_hex(&env.mls_ciphertext),
        env.ttl_seconds,
    )
}

#[test]
fn bridge_round_trips_envelope_wire_bytes() {
    let input = sealed_envelope_json();
    let wire_hex = encode_envelope_json(&input).expect("envelope must encode");
    assert!(wire_hex.starts_with("534e5231"));
    let decoded_json = decode_envelope_json(&wire_hex).expect("envelope must decode");
    assert_eq!(decoded_json, input);
    // Native wire bytes agree with the bridge hex.
    let raw = hex_to_bytes(&wire_hex);
    assert!(decode_envelope(&raw).is_ok());
}

#[test]
fn bridge_round_trips_signed_card_and_verifies_signature() {
    let (input, public) = signed_card_json();
    let wire_hex = encode_card_json(&input).expect("card must encode");
    assert!(wire_hex.starts_with("534e5231"));
    let decoded_json = decode_card_json(&wire_hex).expect("card must decode");
    assert_eq!(decoded_json, input);
    let public_hex = to_hex(&public);
    assert!(verify_card_json(&decoded_json, &public_hex).is_ok());
    // Canonical JCS matches the native signer preimage input.
    let canonical = canonical_card_json(&input).expect("canonical must serialize");
    assert!(canonical.contains("\"card_id\":\"ord-2026-9901\""));
    assert!(canonical.contains("\"did\":\"did:web:air.example.com\""));
    // Native decoder accepts the bridge-produced bytes.
    let raw = hex_to_bytes(&wire_hex);
    assert_eq!(
        decode_card(&raw).map(|card| card.card_id),
        Ok("ord-2026-9901".to_string())
    );
}

#[test]
fn bridge_rejects_malformed_input_with_typed_errors() {
    assert!(matches!(
        encode_card_json("not json"),
        Err(BridgeError::MalformedJson)
    ));
    assert!(matches!(
        encode_card_json("{\"card_id\":\"x\"}"),
        Err(BridgeError::MissingField(_))
    ));
    assert!(matches!(
        encode_envelope_json(&sealed_envelope_json().replace("600", "7")),
        Err(BridgeError::InvalidField(_))
    ));
    assert!(matches!(
        decode_card_json("zz"),
        Err(BridgeError::InvalidHex)
    ));
    assert!(matches!(
        decode_envelope_json(&"00".repeat(8)),
        Err(BridgeError::Wire(_))
    ));
}

#[test]
fn bridge_exports_pinned_interop_vector() {
    let vector = export_vector_json();
    assert!(vector.contains("\"card-vector-m7-001\""));
    assert!(vector.contains("\"wire_frame_hex\""));
    let frame_hex = field(&vector, "wire_frame_hex");
    let raw = hex_to_bytes(frame_hex);
    let card = decode_card(&raw).expect("vector frame must decode");
    assert_eq!(card.card_id, "card-vector-m7-001");
}

fn field<'a>(raw: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\":\"");
    let start = raw.find(&needle).expect("vector field must exist") + needle.len();
    let rest = &raw[start..];
    let end = rest.find('"').expect("vector field must terminate");
    &rest[..end]
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
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
