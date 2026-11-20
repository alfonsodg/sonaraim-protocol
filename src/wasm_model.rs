//! Bridge card/envelope model builders over the minimal JSON parser.
//!
//! Single responsibility: convert parsed JSON pieces into validated
//! protocol types (and back) for the [] entry points.

use crate::card::{validate_card, CardComponent, ComponentType, MerchantSignature, SonaraimCard};
use crate::crypto::to_hex;
use crate::envelope::{validate_envelope, SealedEnvelope};
use crate::wasm_bridge::BridgeError;
use crate::wasm_parse::{component_slices, escape_json, hex_to_bytes, string_field, uint_field};

/// Parses a bridge card JSON object into a [`SonaraimCard`].
pub(crate) fn parse_card(raw: &str) -> Result<SonaraimCard, BridgeError> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(BridgeError::MalformedJson);
    }
    let card_id = string_field(trimmed, "card_id")?;
    let title = string_field(trimmed, "title")?;
    let summary = string_field(trimmed, "summary")?;
    let did = string_field(trimmed, "did")?;
    let algorithm = string_field(trimmed, "algorithm")?;
    let signature_hex = string_field(trimmed, "signature_hex")?;
    let mut components = Vec::new();
    for slice in component_slices(trimmed)? {
        let kind = string_field(slice, "type")?;
        let label = string_field(slice, "label")?;
        let value = string_field(slice, "value").unwrap_or_default();
        let action_uri = string_field(slice, "action_uri").unwrap_or_default();
        components.push(CardComponent {
            component_type: ComponentType::from_wire_str(&kind),
            label,
            value: if value.is_empty() { None } else { Some(value) },
            action_uri: if action_uri.is_empty() {
                None
            } else {
                Some(action_uri)
            },
        });
    }
    let card = SonaraimCard {
        card_id,
        title,
        summary,
        components,
        merchant_signature: MerchantSignature {
            did,
            algorithm,
            signature_hex,
        },
    };
    validate_card(&card).map_err(|_| BridgeError::InvalidCard("card validation failed"))?;
    Ok(card)
}

/// Serializes a [`SonaraimCard`] into the bridge JSON schema.
pub(crate) fn card_to_json(card: &SonaraimCard) -> String {
    let mut comps = String::new();
    for (idx, comp) in card.components.iter().enumerate() {
        if idx > 0 {
            comps.push(',');
        }
        let kind = match &comp.component_type {
            ComponentType::TextBlock => "text_block",
            ComponentType::MediaImage => "media_image",
            ComponentType::KeyValueRow => "key_value_row",
            ComponentType::ActionButton => "action_button",
            ComponentType::Unsupported(raw) => raw.as_str(),
        };
        comps.push_str(&format!(
            "{{\"type\":\"{}\",\"label\":\"{}\",\"value\":\"{}\",\"action_uri\":\"{}\"}}",
            escape_json(kind),
            escape_json(&comp.label),
            escape_json(comp.value.as_deref().unwrap_or("")),
            escape_json(comp.action_uri.as_deref().unwrap_or("")),
        ));
    }
    format!(
        concat!(
            "{{\"card_id\":\"{}\",\"title\":\"{}\",\"summary\":\"{}\",",
            "\"components\":[{}],\"did\":\"{}\",\"algorithm\":\"{}\",",
            "\"signature_hex\":\"{}\"}}",
        ),
        escape_json(&card.card_id),
        escape_json(&card.title),
        escape_json(&card.summary),
        comps,
        escape_json(&card.merchant_signature.did),
        escape_json(&card.merchant_signature.algorithm),
        escape_json(&card.merchant_signature.signature_hex),
    )
}

/// Parses a bridge envelope JSON object into a [`SealedEnvelope`].
pub(crate) fn parse_envelope(raw: &str) -> Result<SealedEnvelope, BridgeError> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(BridgeError::MalformedJson);
    }
    let mailbox_id = string_field(trimmed, "mailbox_id")?;
    let ephemeral_pub_key = hex_to_bytes(&string_field(trimmed, "ephemeral_pub_key")?)?;
    let mls_ciphertext = hex_to_bytes(&string_field(trimmed, "mls_ciphertext")?)?;
    let ttl_seconds = uint_field(trimmed, "ttl_seconds")?;
    let env = SealedEnvelope {
        mailbox_id,
        ephemeral_pub_key,
        mls_ciphertext,
        ttl_seconds,
    };
    validate_envelope(&env).map_err(|_| BridgeError::InvalidField("envelope bounds"))?;
    Ok(env)
}

/// Serializes a [`SealedEnvelope`] into the bridge JSON schema.
pub(crate) fn envelope_to_json(env: &SealedEnvelope) -> String {
    format!(
        concat!(
            "{{\"mailbox_id\":\"{}\",\"ephemeral_pub_key\":\"{}\",",
            "\"mls_ciphertext\":\"{}\",\"ttl_seconds\":{}}}",
        ),
        escape_json(&env.mailbox_id),
        to_hex(&env.ephemeral_pub_key),
        to_hex(&env.mls_ciphertext),
        env.ttl_seconds,
    )
}
