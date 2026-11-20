//! RFC 8785 canonical JSON (JCS) subset for Sonaraim cards.
//!
//! Provides deterministic canonical bytes for [`SonaraimCard`] signing, the
//! domain-separated preimage layout shared with cross-runtime verifiers
//! (`scripts/verify-vectors.mjs`, `tests/vectors/v1.json`), and the
//! Ed25519 card sign/verify entry points over that preimage.
//!
//! Field values are escaped per RFC 8785 §3.2.2.3 so quotes, backslashes, and
//! C0 control characters in legal card fields cannot break canonicality.

use crate::card::{validate_card, ComponentType, SonaraimCard};
use crate::crypto::{
    ed25519_verify_bytes, to_hex, CryptoError, CARD_SIGNATURE_CONTEXT, SONARAIM_JCS_VERSION,
};

/// Escapes a string per RFC 8785 §3.2.2.3: `"` and `\` take short escapes,
/// C0 controls take short escapes where defined (`\b \f \n \r \t`) and
/// `\u00XX` otherwise; all other characters (including DEL and non-ASCII)
/// pass through verbatim.
pub fn escape_jcs_str(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Produces deterministic canonical JCS-ordered bytes for signing a [`SonaraimCard`].
pub fn canonical_card_bytes(card: &SonaraimCard) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("{\"card_id\":\"");
    out.push_str(&escape_jcs_str(&card.card_id));
    out.push_str("\",\"components\":[");
    for (idx, comp) in card.components.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        let kind = match &comp.component_type {
            ComponentType::TextBlock => "text_block",
            ComponentType::MediaImage => "media_image",
            ComponentType::KeyValueRow => "key_value_row",
            ComponentType::ActionButton => "action_button",
            ComponentType::Unsupported(raw) => raw.as_str(),
        };
        out.push_str("{\"action_uri\":\"");
        out.push_str(&escape_jcs_str(comp.action_uri.as_deref().unwrap_or("")));
        out.push_str("\",\"label\":\"");
        out.push_str(&escape_jcs_str(&comp.label));
        out.push_str("\",\"type\":\"");
        out.push_str(&escape_jcs_str(kind));
        out.push_str("\",\"value\":\"");
        out.push_str(&escape_jcs_str(comp.value.as_deref().unwrap_or("")));
        out.push_str("\"}");
    }
    out.push_str("],\"did\":\"");
    out.push_str(&escape_jcs_str(&card.merchant_signature.did));
    out.push_str("\",\"summary\":\"");
    out.push_str(&escape_jcs_str(&card.summary));
    out.push_str("\",\"title\":\"");
    out.push_str(&escape_jcs_str(&card.title));
    out.push_str("\"}");
    out.into_bytes()
}

/// Builds the domain-separated preimage signed for a card payload.
///
/// Layout: `jcs_version (0x1f) signature_context (0x1f) canonical_jcs`.
/// Cross-runtime verifiers must reconstruct this exact byte string before
/// Ed25519 verification (see `scripts/verify-vectors.mjs`).
pub fn card_signing_preimage(
    canonical: &[u8],
    jcs_version: &str,
    signature_context: &str,
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(jcs_version.len() + 1 + signature_context.len() + 1 + canonical.len());
    msg.extend_from_slice(jcs_version.as_bytes());
    msg.push(0x1f);
    msg.extend_from_slice(signature_context.as_bytes());
    msg.push(0x1f);
    msg.extend_from_slice(canonical);
    msg
}

/// Signs a [`SonaraimCard`] using its canonical JCS representation and a 32-byte Ed25519 seed.
pub fn sign_card_jcs(card: &mut SonaraimCard, secret: &[u8; 32]) -> Result<(), CryptoError> {
    let signing = ed25519_dalek::SigningKey::from_bytes(secret);
    let canonical = canonical_card_bytes(card);
    let message = card_signing_preimage(&canonical, SONARAIM_JCS_VERSION, CARD_SIGNATURE_CONTEXT);
    use ed25519_dalek::Signer;
    let signature = signing.sign(&message);
    card.merchant_signature.algorithm = "Ed25519".to_string();
    card.merchant_signature.signature_hex = to_hex(&signature.to_bytes());
    validate_card(card).map_err(CryptoError::InvalidCard)
}

/// Verifies a [`SonaraimCard`] signature against the merchant's 32-byte Ed25519 public key.
pub fn verify_card_jcs(card: &SonaraimCard, public_key: &[u8; 32]) -> Result<(), CryptoError> {
    validate_card(card).map_err(CryptoError::InvalidCard)?;
    let signature = crate::crypto::decode_signature_hex(&card.merchant_signature.signature_hex)?;
    let canonical = canonical_card_bytes(card);
    let message = card_signing_preimage(&canonical, SONARAIM_JCS_VERSION, CARD_SIGNATURE_CONTEXT);
    ed25519_verify_bytes(public_key, &message, &signature)
}
