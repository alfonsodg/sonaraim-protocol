//! Milestone 7 TDD suite for `sonaraim-protocol` (Issue #5), extended by Issue #8.
//!
//! Verifies the sliding-window anti-replay guard (`ReplayWindow`) for sealed
//! envelopes and group-ratchet epochs, validates deterministic cross-runtime
//! (`export_canonical_test_vector` plus the versioned `tests/vectors/v1.json`
//! bundle), and pins the JCS version string verified from Node.js via
//! `node scripts/verify-vectors.mjs tests/vectors/v1.json` (not executed here).

use sonaraim_protocol::crypto::{
    card_signing_preimage, ed25519_public_key_bytes, to_hex, verify_card_jcs, SONARAIM_JCS_VERSION,
};
use sonaraim_protocol::replay::{ReplayError, ReplayWindow};
use sonaraim_protocol::wire::{decode_card, export_canonical_test_vector};

#[test]
fn replay_window_rejects_duplicate_envelope_and_stale_epoch() {
    let mut window = ReplayWindow::new(3);
    assert_eq!(window.capacity(), 3);
    assert_eq!(window.len(), 0);
    assert!(window.is_empty());
    assert_eq!(window.min_epoch(), 0);

    // First valid envelope at epoch 1
    assert_eq!(window.check_and_record("env-001", 1), Ok(()));
    assert_eq!(window.len(), 1);
    assert_eq!(window.min_epoch(), 1);

    // Duplicate envelope ID at same or higher epoch must be rejected
    assert_eq!(
        window.check_and_record("env-001", 1),
        Err(ReplayError::DuplicateEnvelope("env-001".to_string()))
    );
    assert_eq!(
        window.check_and_record("env-001", 2),
        Err(ReplayError::DuplicateEnvelope("env-001".to_string()))
    );

    // Stale group epoch (< current min_epoch) must be rejected without recording envelope
    assert_eq!(
        window.check_and_record("env-002", 0),
        Err(ReplayError::StaleEpoch {
            provided: 0,
            min_required: 1,
        })
    );
    assert!(!window.contains("env-002"));

    // Empty envelope ID must be rejected
    assert_eq!(
        window.check_and_record("   ", 1),
        Err(ReplayError::EmptyEnvelopeId)
    );
}

#[test]
fn replay_window_evicts_oldest_entries_in_fifo_order() {
    let mut window = ReplayWindow::new(2);
    assert_eq!(window.check_and_record("env-a", 10), Ok(()));
    assert_eq!(window.check_and_record("env-b", 10), Ok(()));
    assert_eq!(window.len(), 2);
    assert!(window.contains("env-a"));
    assert!(window.contains("env-b"));

    // Recording a 3rd distinct envelope evicts "env-a" (FIFO) and advances epoch to 11
    assert_eq!(window.check_and_record("env-c", 11), Ok(()));
    assert_eq!(window.len(), 2);
    assert!(!window.contains("env-a"));
    assert!(window.contains("env-b"));
    assert!(window.contains("env-c"));

    // "env-b" is still in window -> rejected
    assert_eq!(
        window.check_and_record("env-b", 11),
        Err(ReplayError::DuplicateEnvelope("env-b".to_string()))
    );

    // "env-a" was evicted -> accepted at current epoch 11, evicting "env-b"
    assert_eq!(window.check_and_record("env-a", 11), Ok(()));
    assert!(!window.contains("env-b"));
    assert!(window.contains("env-c"));
    assert!(window.contains("env-a"));
}

#[test]
fn canonical_test_vector_is_deterministic_and_verifiable() {
    let json_a = export_canonical_test_vector();
    let json_b = export_canonical_test_vector();
    assert_eq!(json_a, json_b);

    assert!(json_a.contains("\"card_id\":\"card-vector-m7-001\""));
    assert!(json_a.contains("\"canonical_jcs\":\"{"));
    assert!(json_a.contains("\"public_key_hex\":\""));
    assert!(json_a.contains("\"signature_hex\":\""));
    assert!(json_a.contains("\"wire_frame_hex\":\"534e5231"));

    // Extract wire_frame_hex from the JSON vector and verify round-trip + signature
    let marker = "\"wire_frame_hex\":\"";
    let start = json_a.find(marker).map(|i| i + marker.len()).unwrap_or(0);
    let end = json_a[start..]
        .find('"')
        .map(|i| start + i)
        .unwrap_or(start);
    let frame_hex = &json_a[start..end];

    let mut frame_bytes = Vec::with_capacity(frame_hex.len() / 2);
    let bytes = frame_hex.as_bytes();
    let mut idx = 0;
    while idx + 1 < bytes.len() {
        let hi = (bytes[idx] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[idx + 1] as char).to_digit(16).unwrap_or(0) as u8;
        frame_bytes.push((hi << 4) | lo);
        idx += 2;
    }

    let decoded = decode_card(&frame_bytes);
    assert!(decoded.is_ok());
    if let Ok(card) = decoded {
        let secret = [0x07u8; 32];
        let pub_key = ed25519_public_key_bytes(&secret);
        assert!(json_a.contains(&to_hex(&pub_key)));
        assert_eq!(verify_card_jcs(&card, &pub_key), Ok(()));
    }
}

#[test]
fn versioned_vectors_bundle_pins_jcs_version_and_signing_preimage() {
    assert_eq!(SONARAIM_JCS_VERSION, "sonaraim-jcs-v1");

    let raw = std::fs::read_to_string("tests/vectors/v1.json").expect("v1.json must exist");
    assert!(raw.contains("\"format\":\"sonaraim-vectors-v1\""));
    assert!(raw.contains("\"jcs_version\":\"sonaraim-jcs-v1\""));
    assert!(raw.contains("\"signature_context\":\"sonaraim-card-ed25519-v1\""));
    assert!(raw.contains("\"signing_preimage_hex\":\""));

    // The Node.js cross-runtime check reconstructs the exact signed preimage
    // (version + 0x1f + context + 0x1f + canonical JCS) and verifies Ed25519:
    // `node scripts/verify-vectors.mjs tests/vectors/v1.json` (manual step,
    // executed locally during development — not part of `cargo test`).
    let marker = "\"canonical_jcs\":\"";
    let start = raw.find(marker).map(|i| i + marker.len()).unwrap_or(0);
    let end = raw[start..]
        .find("\",\"signature_context\"")
        .map(|i| start + i)
        .unwrap_or(start);
    let escaped = &raw[start..end];
    let canonical = escaped.replace("\\\"", "\"").replace("\\\\", "\\");
    let preimage = card_signing_preimage(canonical.as_bytes());
    let preimage_hex = to_hex(&preimage);
    assert!(raw.contains(&preimage_hex));
}
