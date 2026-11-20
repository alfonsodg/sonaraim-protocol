//! JSON bridge entry points over the parsed card/envelope models.
//!
//! Thin public API over [`crate::wasm_bridge`]: JSON in, wire-frame hex out
//! (and back), canonical JCS bytes, card verification, and the pinned
//! interop vector. Single responsibility: wire the parser to the codec.

use crate::crypto::{canonical_card_bytes, decode_signature_hex, to_hex, verify_card_jcs};
use crate::wasm_bridge::BridgeError;
use crate::wasm_model::{card_to_json, envelope_to_json, parse_card, parse_envelope};
use crate::wasm_parse::hex_to_bytes;
use crate::wire::{decode_card, decode_envelope, encode_card, encode_envelope};

/// Encodes an envelope JSON object into `SNR1` wire-frame hex.
pub fn encode_envelope_json(input: &str) -> Result<String, BridgeError> {
    let env = parse_envelope(input)?;
    Ok(to_hex(&encode_envelope(&env)?))
}

/// Decodes `SNR1` wire-frame hex into an envelope JSON object.
pub fn decode_envelope_json(wire_hex: &str) -> Result<String, BridgeError> {
    let raw = hex_to_bytes(wire_hex)?;
    Ok(envelope_to_json(&decode_envelope(&raw)?))
}

/// Encodes a card JSON object into `SNR1` wire-frame hex.
pub fn encode_card_json(input: &str) -> Result<String, BridgeError> {
    let card = parse_card(input)?;
    Ok(to_hex(&encode_card(&card)?))
}

/// Decodes `SNR1` wire-frame hex into a card JSON object.
pub fn decode_card_json(wire_hex: &str) -> Result<String, BridgeError> {
    let raw = hex_to_bytes(wire_hex)?;
    Ok(card_to_json(&decode_card(&raw)?))
}

/// Returns the canonical JCS bytes of a card JSON object as a UTF-8 string.
pub fn canonical_card_json(input: &str) -> Result<String, BridgeError> {
    let card = parse_card(input)?;
    String::from_utf8(canonical_card_bytes(&card)).map_err(|_| BridgeError::InvalidField("card_id"))
}

/// Verifies a card JSON object against a 64-hex-char Ed25519 public key.
pub fn verify_card_json(input: &str, public_key_hex: &str) -> Result<bool, BridgeError> {
    let card = parse_card(input)?;
    let key_bytes = hex_to_bytes(public_key_hex)?;
    if key_bytes.len() != 32 {
        return Err(BridgeError::InvalidHex);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    decode_signature_hex(&card.merchant_signature.signature_hex)
        .map_err(|_| BridgeError::InvalidSignature)?;
    match verify_card_jcs(&card, &key) {
        Ok(()) => Ok(true),
        Err(_) => Err(BridgeError::InvalidSignature),
    }
}

/// Exports the pinned deterministic interop vector as JSON.
pub fn export_vector_json() -> String {
    crate::wire::export_canonical_test_vector()
}
