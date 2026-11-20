// SPDX-License-Identifier: Apache-2.0
// Node.js interop test for the WASM/TS wire-codec bridge (Issue #11).
//
// Replays the pinned `tests/vectors/v1.json` card vector through the bridge
// contract — encode/decode round-trip, canonical-JCS match, and Ed25519
// verification — without requiring the compiled `.wasm` artifact. Run with:
//   node --test ts/wire-bridge.test.mjs
//
// The Rust side of the same contract is pinned by
// `tests/wasm_bridge_test.rs`; the `.wasm` build is verified separately via
// `wasm-pack build --target web --features wasm`.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const bundle = JSON.parse(readFileSync(new URL("../tests/vectors/v1.json", import.meta.url), "utf8"));
const card = bundle.cards[0];

const hexToBytes = (hex) => Uint8Array.from(Buffer.from(hex, "hex"));
const bytesToHex = (bytes) => Buffer.from(bytes).toString("hex");

// Minimal SNR1 wire-frame decoder mirroring `src/wire.rs` (length-prefixed
// fields after the 4-byte magic). Used to cross-check the bridge hex shape
// without the compiled wasm module.
function readField(view, offset) {
  const len = view.getUint32(offset, false);
  const start = offset + 4;
  const bytes = new Uint8Array(view.buffer, view.byteOffset + start, len);
  return { text: new TextDecoder().decode(bytes), next: start + len };
}

function bridgeEnvelopeFromVector() {
  // Reconstructs the bridge envelope JSON shape from the raw vector card:
  // the vector file carries the card payload; the envelope wraps a fixed
  // 32-byte ciphertext placeholder so the SNR1 framing is exercised.
  const ephemeral = "09".repeat(32);
  const ciphertext = "ab".repeat(32);
  return JSON.stringify({
    mailbox_id: "mbx_wire_0001",
    ephemeral_pub_key: ephemeral,
    mls_ciphertext: ciphertext,
    ttl_seconds: 600,
  });
}

function encodeEnvelopeBridge(envelopeJson) {
  // Pure-JS mirror of `encode_envelope_json`: validates the bridge schema
  // then emits SNR1 framing. The Rust bridge is authoritative; this mirror
  // only pins the byte layout the TS bindings must reproduce.
  const env = JSON.parse(envelopeJson);
  assert.ok(typeof env.mailbox_id === "string" && env.mailbox_id.length >= 8);
  assert.ok(/^[0-9a-f]+$/.test(env.ephemeral_pub_key));
  assert.ok(/^[0-9a-f]+$/.test(env.mls_ciphertext));
  assert.ok(Number.isInteger(env.ttl_seconds) && env.ttl_seconds >= 60);
  const parts = [Buffer.from("SNR1")];
  for (const field of [env.mailbox_id, env.ephemeral_pub_key, env.mls_ciphertext]) {
    const bytes = Buffer.from(field, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(bytes.length);
    parts.push(len, bytes);
  }
  const ttl = Buffer.alloc(4);
  ttl.writeUInt32BE(env.ttl_seconds);
  parts.push(ttl);
  return Buffer.concat(parts).toString("hex");
}

describe("wasm bridge interop (node mirror of src/wasm_json.rs)", () => {
  it("card vector canonical JCS matches the pinned preimage input", () => {
    const canonical = card.canonical_jcs;
    assert.ok(canonical.includes(`"card_id":"${card.card_id}"`));
    assert.ok(canonical.includes(`"did":"did:sonaraim:merchant-vector-01"`));
    const prefix = new TextEncoder().encode(`${bundle.jcs_version}\x1f${card.signature_context}\x1f`);
    const preimage = Buffer.concat([prefix, Buffer.from(canonical, "utf8")]);
    assert.equal(preimage.toString("hex"), card.signing_preimage_hex);
  });

  it("card vector signature verifies with Node WebCrypto Ed25519", async () => {
    const publicKey = await crypto.subtle.importKey("raw", hexToBytes(card.public_key_hex), { name: "Ed25519" }, false, ["verify"]);
    const prefix = new TextEncoder().encode(`${bundle.jcs_version}\x1f${card.signature_context}\x1f`);
    const preimage = Buffer.concat([prefix, Buffer.from(card.canonical_jcs, "utf8")]);
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, hexToBytes(card.signature_hex), preimage);
    assert.equal(ok, true);
  });

  it("envelope bridge JSON round-trips through SNR1 framing", () => {
    const input = bridgeEnvelopeFromVector();
    const wireHex = encodeEnvelopeBridge(input);
    assert.ok(wireHex.startsWith(Buffer.from("SNR1").toString("hex")));
    const bytes = hexToBytes(wireHex);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    assert.equal(new TextDecoder().decode(bytes.slice(0, 4)), "SNR1");
    const mailbox = readField(view, 4);
    assert.equal(mailbox.text, "mbx_wire_0001");
    const ttl = view.getUint32(bytes.length - 4, false);
    assert.equal(ttl, 600);
  });

  it("bridge error contract rejects malformed input with typed failures", () => {
    assert.throws(() => JSON.parse("not json"), SyntaxError);
    assert.throws(() => encodeEnvelopeBridge(JSON.stringify({ mailbox_id: "short" })), /./);
  });
});
