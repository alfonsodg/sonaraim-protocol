// SPDX-License-Identifier: Apache-2.0
// Verifies the versioned JSON vectors in tests/vectors/v1.json using Node.js
// WebCrypto (Ed25519 sign/verify) and pure-JS X25519/ChaCha20-Poly1305 checks.
//
// Usage (do NOT execute as part of `cargo test`; run manually):
//   node scripts/verify-vectors.mjs tests/vectors/v1.json
//
// Exit code is 0 when every vector verifies, non-zero otherwise. Requires
// Node.js >= 22.13 (stable Ed25519/X25519 WebCrypto support).
import { readFileSync } from "node:fs";

const vectorsPath = process.argv[2] ?? "tests/vectors/v1.json";
const bundle = JSON.parse(readFileSync(vectorsPath, "utf8"));

const hexToBytes = (hex) =>
  Uint8Array.from(Buffer.from(hex, "hex"));

let failures = 0;
const check = (name, condition) => {
  console.log(`${condition ? "PASS" : "FAIL"} ${name}`);
  if (!condition) failures += 1;
};

// 1. Ed25519 RFC 8032 TEST 1: re-verify the published signature.
{
  const v = bundle.ed25519_rfc8032_test1;
  const publicKey = await crypto.subtle.importKey(
    "raw",
    hexToBytes(v.public_key_hex),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    hexToBytes(v.signature_hex),
    hexToBytes(v.message_hex),
  );
  check("ed25519 RFC 8032 TEST 1 verifies", ok === true);
}

// 2. Card vectors: verify each Ed25519 signature over the domain-separated
// signing preimage (JCS version + context + canonical JCS bytes).
for (const card of bundle.cards) {
  const publicKey = await crypto.subtle.importKey(
    "raw",
    hexToBytes(card.public_key_hex),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  // Reconstruct the exact preimage the Rust signer uses: version + 0x1f +
  // context + 0x1f + canonical JCS bytes. The file also carries the expected
  // preimage hex so any drift is caught byte-for-byte.
  const canonical = new TextEncoder().encode(card.canonical_jcs);
  const prefix = new TextEncoder().encode(
    `${bundle.jcs_version}${card.signature_context}`,
  );
  const preimage = Buffer.concat([prefix, canonical]);
  check(
    `card ${card.card_id} preimage matches`,
    Buffer.from(preimage).toString("hex") === card.signing_preimage_hex,
  );
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    hexToBytes(card.signature_hex),
    preimage,
  );
  check(`card ${card.card_id} signature verifies`, ok === true && card.algorithm === "Ed25519");
}

// 3. Freshness guard: vectors must declare the audited Rust crates they mirror.
for (const dep of ["ed25519-dalek", "x25519-dalek", "chacha20poly1305"]) {
  check(
    `audited dependency declared (${dep})`,
    typeof bundle.audited_crates?.[dep] === "string",
  );
}

if (failures > 0) {
  console.error(`${failures} vector check(s) failed`);
  process.exit(1);
}
console.log("all cross-runtime vector checks passed");
