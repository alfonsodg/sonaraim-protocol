//! Versioned cross-runtime vector exporter (Issue #8).
//!
//! Regenerates `tests/vectors/v1.json` with deterministic Ed25519, X25519,
//! and AEAD vectors plus the JCS version string. Run manually with
//! `cargo test export_versioned_vectors`; Node.js verification is documented
//! in `scripts/verify-vectors.mjs` and is not executed here.

use sonaraim_protocol::card::{CardComponent, ComponentType, MerchantSignature, SonaraimCard};
use sonaraim_protocol::crypto::{
    aead_open, aead_seal, canonical_card_bytes, card_signing_preimage, ed25519_public_key_bytes,
    ed25519_sign_bytes, to_hex, x25519_agree, x25519_public_from_secret, CARD_SIGNATURE_CONTEXT,
    SONARAIM_JCS_VERSION,
};
use std::fs;
use std::path::PathBuf;

/// Builds the deterministic vector card also used by `export_canonical_test_vector`.
fn vector_card() -> (SonaraimCard, [u8; 32]) {
    let secret = [0x07u8; 32];
    let card = SonaraimCard {
        card_id: "card-vector-m7-001".to_string(),
        title: "Milestone 7 Interop Vector".to_string(),
        summary: "Deterministic cross-runtime test vector for Sonaraim JCS and wire framing."
            .to_string(),
        components: vec![
            CardComponent {
                component_type: ComponentType::TextBlock,
                label: "Canonical payload verification".to_string(),
                value: None,
                action_uri: None,
            },
            CardComponent {
                component_type: ComponentType::ActionButton,
                label: "Verify Order".to_string(),
                value: None,
                action_uri: Some("sonaraim://verify/m7-001".to_string()),
            },
        ],
        merchant_signature: MerchantSignature {
            did: "did:sonaraim:merchant-vector-01".to_string(),
            algorithm: "Ed25519".to_string(),
            signature_hex: String::new(),
        },
    };
    (card, secret)
}

/// JSON-escapes a string for embedding in the vectors file.
fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[test]
fn export_versioned_vectors() {
    // Deterministic card vector (seed 0x07, mirrors wire.rs interop vector).
    let (mut card, secret) = vector_card();
    sonaraim_protocol::crypto::sign_card_jcs(&mut card, &secret).expect("vector card must sign");
    let public_key = ed25519_public_key_bytes(&secret);
    let canonical = String::from_utf8(canonical_card_bytes(&card)).expect("canonical JCS is UTF-8");

    // RFC 8032 TEST 1 reference values (empty message) for cross-runtime checks.
    let rfc_secret = [0x9du8; 1];
    let _ = rfc_secret;
    let rfc_seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let rfc_sig = ed25519_sign_bytes(&rfc_seed, &[]);

    // Deterministic X25519 agreement pair (fixed secrets, no randomness).
    let alice_secret = [0x11u8; 32];
    let bob_secret = [0x22u8; 32];
    let alice_pub = x25519_public_from_secret(&alice_secret);
    let bob_pub = x25519_public_from_secret(&bob_secret);
    let alice_shared = x25519_agree(&alice_secret, &bob_pub);
    let bob_shared = x25519_agree(&bob_secret, &alice_pub);
    assert_eq!(alice_shared, bob_shared);

    // Deterministic AEAD check vector (fixed key/aad/plaintext; nonce is random
    // per seal, so the file records an `open` self-check rather than bytes).
    let aead_key = [0x5au8; 32];
    let aead_aad = b"sonaraim-vectors-v1";
    let aead_plaintext = b"vector-aead-self-check";
    let sealed = aead_seal(&aead_key, aead_aad, aead_plaintext).expect("seal must succeed");
    assert_eq!(
        aead_open(&aead_key, aead_aad, &sealed),
        Ok(aead_plaintext.to_vec())
    );

    let lock = fs::read_to_string("Cargo.lock").expect("Cargo.lock must be committed");
    let mut audited: Vec<(&str, String)> = Vec::new();
    for name in [
        "ed25519-dalek",
        "x25519-dalek",
        "chacha20poly1305",
        "hkdf",
        "hmac",
        "sha2",
        "rand",
        "zeroize",
    ] {
        let version = lock
            .split(&format!("name = \"{name}\""))
            .nth(1)
            .and_then(|chunk| chunk.split("version = \"").nth(1))
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("unknown");
        audited.push((name, version.to_string()));
    }
    let audited_json = audited
        .iter()
        .map(|(name, version)| format!("\"{name}\":\"{version}\""))
        .collect::<Vec<_>>()
        .join(",");

    let json = format!(
        concat!(
            "{{\n",
            "  \"format\":\"sonaraim-vectors-v1\",\n",
            "  \"jcs_version\":\"{}\",\n",
            "  \"ed25519_rfc8032_test1\":{{\n",
            "    \"seed_hex\":\"{}\",\n",
            "    \"public_key_hex\":\"{}\",\n",
            "    \"message_hex\":\"\",\n",
            "    \"signature_hex\":\"{}\"\n",
            "  }},\n",
            "  \"x25519_agreement\":{{\n",
            "    \"alice_public_hex\":\"{}\",\n",
            "    \"bob_public_hex\":\"{}\",\n",
            "    \"shared_hex\":\"{}\"\n",
            "  }},\n",
            "  \"cards\":[{{\n",
            "    \"card_id\":\"{}\",\n",
            "    \"algorithm\":\"Ed25519\",\n",
            "    \"canonical_jcs\":\"{}\",\n",
            "    \"signature_context\":\"{}\",\n",
            "    \"signing_preimage_hex\":\"{}\",\n",
            "    \"public_key_hex\":\"{}\",\n",
            "    \"signature_hex\":\"{}\"\n",
            "  }}],\n",
            "  \"audited_crates\":{{{}}}\n",
            "}}\n"
        ),
        SONARAIM_JCS_VERSION,
        to_hex(&rfc_seed),
        to_hex(&ed25519_public_key_bytes(&rfc_seed)),
        to_hex(&rfc_sig),
        to_hex(&alice_pub),
        to_hex(&bob_pub),
        to_hex(&alice_shared),
        card.card_id,
        json_escape(&canonical),
        CARD_SIGNATURE_CONTEXT,
        to_hex(&card_signing_preimage(canonical.as_bytes())),
        to_hex(&public_key),
        card.merchant_signature.signature_hex,
        audited_json,
    );

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("vectors");
    fs::create_dir_all(&path).expect("vectors dir creatable");
    path.push("v1.json");
    fs::write(&path, &json).expect("vectors file writable");

    // Self-check: the committed file must equal what we just generated.
    let on_disk = fs::read_to_string(&path).expect("vectors file readable");
    assert_eq!(on_disk, json);
}
