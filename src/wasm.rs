//! WebAssembly entry points for the Sonaraim wire-codec JSON bridge.
//!
//! Compiled only with the `wasm` cargo feature (`wasm-pack build --target
//! web --features wasm`); native builds use [`crate::wasm_bridge`] directly
//! with zero extra dependencies. Each export is a thin string wrapper so
//! the `.wasm` module and the native tests verify identical behavior.

#[cfg(feature = "wasm")]
mod wasm_bindgen_api {
    use crate::wasm_json::{
        canonical_card_json, decode_card_json, decode_envelope_json, encode_card_json,
        encode_envelope_json, export_vector_json, verify_card_json,
    };
    use wasm_bindgen::prelude::wasm_bindgen;

    /// Encodes an envelope JSON object into `SNR1` wire-frame hex.
    #[wasm_bindgen]
    pub fn encode_envelope(input: &str) -> Result<String, String> {
        encode_envelope_json(input).map_err(|err| err.to_string())
    }

    /// Decodes `SNR1` wire-frame hex into an envelope JSON object.
    #[wasm_bindgen]
    pub fn decode_envelope(wire_hex: &str) -> Result<String, String> {
        decode_envelope_json(wire_hex).map_err(|err| err.to_string())
    }

    /// Encodes a card JSON object into `SNR1` wire-frame hex.
    #[wasm_bindgen]
    pub fn encode_card(input: &str) -> Result<String, String> {
        encode_card_json(input).map_err(|err| err.to_string())
    }

    /// Decodes `SNR1` wire-frame hex into a card JSON object.
    #[wasm_bindgen]
    pub fn decode_card(wire_hex: &str) -> Result<String, String> {
        decode_card_json(wire_hex).map_err(|err| err.to_string())
    }

    /// Returns the canonical JCS bytes of a card JSON object.
    #[wasm_bindgen]
    pub fn canonical_card_bytes(input: &str) -> Result<String, String> {
        canonical_card_json(input).map_err(|err| err.to_string())
    }

    /// Verifies a card JSON object against an Ed25519 public key hex string.
    #[wasm_bindgen]
    pub fn verify_card(input: &str, public_key_hex: &str) -> Result<bool, String> {
        verify_card_json(input, public_key_hex).map_err(|err| err.to_string())
    }

    /// Exports the pinned deterministic interop vector as JSON.
    #[wasm_bindgen]
    pub fn export_canonical_test_vector() -> String {
        export_vector_json()
    }
}
