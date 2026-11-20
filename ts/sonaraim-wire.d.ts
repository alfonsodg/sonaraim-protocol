// SPDX-License-Identifier: Apache-2.0
// Type declarations for the `wasm` feature bindings in `src/wasm.rs`
// (built with `wasm-pack build --target web --features wasm`).
//
// The compiled module exposes the same JSON bridge pinned by
// `tests/wasm_bridge_test.rs`: JSON in, `SNR1` wire-frame hex out (and
// back), canonical JCS bytes, card verification, and the pinned vector.
// Errors surface as thrown `Error` with the `BridgeError` display text.

/** Declarative card component in bridge JSON shape. */
export interface BridgeComponent {
  type: "text_block" | "media_image" | "key_value_row" | "action_button" | string;
  label: string;
  value: string;
  action_uri: string;
}

/** Sonaraim card in bridge JSON shape (mirrors `SonaraimCard`). */
export interface BridgeCard {
  card_id: string;
  title: string;
  summary: string;
  components: BridgeComponent[];
  did: string;
  algorithm: "Ed25519";
  signature_hex: string;
}

/** Sealed Sender envelope in bridge JSON shape. */
export interface BridgeEnvelope {
  mailbox_id: string;
  ephemeral_pub_key: string;
  mls_ciphertext: string;
  ttl_seconds: number;
}

/** Pinned interop vector (`export_canonical_test_vector`). */
export interface BridgeVector {
  card_id: string;
  canonical_jcs: string;
  public_key_hex: string;
  signature_hex: string;
  wire_frame_hex: string;
}

/** Encodes an envelope JSON object into `SNR1` wire-frame hex. */
export function encode_envelope(input: string): string;
/** Decodes `SNR1` wire-frame hex into an envelope JSON object. */
export function decode_envelope(wire_hex: string): string;
/** Encodes a card JSON object into `SNR1` wire-frame hex. */
export function encode_card(input: string): string;
/** Decodes `SNR1` wire-frame hex into a card JSON object. */
export function decode_card(wire_hex: string): string;
/** Returns the canonical JCS bytes of a card JSON object. */
export function canonical_card_bytes(input: string): string;
/** Verifies a card JSON object against an Ed25519 public key hex string. */
export function verify_card(input: string, public_key_hex: string): boolean;
/** Exports the pinned deterministic interop vector as JSON. */
export function export_canonical_test_vector(): string;
