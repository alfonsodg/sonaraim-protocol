//! Minimal JSON object parser for the WASM bridge schema.
//!
//! Hand-rolled string/uint field extraction with `\"`/`\\` escape handling
//! (no `serde`, keeping native builds dependency-free). Single responsibility:
//! turn bridge JSON text into borrowed pieces for the model builders.

use crate::wasm_bridge::BridgeError;

/// Splits the raw `components` array into per-component object slices.
pub(crate) fn component_slices(raw: &str) -> Result<Vec<&str>, BridgeError> {
    let needle = "\"components\"";
    let start = raw.find(needle).ok_or(BridgeError::MissingField("field"))?;
    let after_key = raw[start + needle.len()..].trim_start();
    let array = after_key
        .strip_prefix(':')
        .ok_or(BridgeError::MalformedJson)?
        .trim_start()
        .strip_prefix('[')
        .ok_or(BridgeError::MalformedJson)?;
    let mut slices = Vec::new();
    let mut depth = 0usize;
    let mut current: Option<usize> = None;
    for (idx, ch) in array.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    current = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    return Err(BridgeError::MalformedJson);
                }
                depth -= 1;
                if depth == 0 {
                    let begin = current.ok_or(BridgeError::MalformedJson)?;
                    slices.push(&array[begin..=idx]);
                }
            }
            ']' if depth == 0 => break,
            _ => {}
        }
    }
    if depth != 0 {
        return Err(BridgeError::MalformedJson);
    }
    Ok(slices)
}

/// Escapes a string for embedding in bridge JSON output.
pub(crate) fn escape_json(raw: &str) -> String {
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

/// Decodes lowercase hex into bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, BridgeError> {
    if !hex.len().is_multiple_of(2) || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BridgeError::InvalidHex);
    }
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = (bytes[idx] as char)
            .to_digit(16)
            .ok_or(BridgeError::InvalidHex)? as u8;
        let lo = (bytes[idx + 1] as char)
            .to_digit(16)
            .ok_or(BridgeError::InvalidHex)? as u8;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

/// Extracts a top-level string field from a flat JSON object.
///
/// Handles `\"` and `\\` escapes; rejects nested objects.
pub(crate) fn string_field(raw: &str, key: &str) -> Result<String, BridgeError> {
    let needle = format!("\"{key}\"");
    let mut cursor = raw
        .find(needle.as_str())
        .ok_or(BridgeError::MissingField(field_name(key)))?;
    cursor += needle.len();
    let rest = raw[cursor..].trim_start();
    let after_colon = rest.strip_prefix(':').ok_or(BridgeError::MalformedJson)?;
    let value = after_colon.trim_start();
    if !value.starts_with('"') {
        return Err(BridgeError::MalformedJson);
    }
    let mut out = String::new();
    let mut chars = value[1..].chars();
    loop {
        let ch = chars.next().ok_or(BridgeError::MalformedJson)?;
        match ch {
            '"' => break,
            '\\' => {
                let escaped = chars.next().ok_or(BridgeError::MalformedJson)?;
                match escaped {
                    '"' | '\\' | '/' => out.push(escaped),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let digits: String = chars.by_ref().take(4).collect();
                        if digits.len() != 4 {
                            return Err(BridgeError::MalformedJson);
                        }
                        let code = u32::from_str_radix(&digits, 16)
                            .map_err(|_| BridgeError::MalformedJson)?;
                        out.push(char::from_u32(code).ok_or(BridgeError::MalformedJson)?);
                    }
                    _ => return Err(BridgeError::MalformedJson),
                }
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// Maps a field key to a stable name for [`BridgeError::MissingField`].
pub(crate) fn field_name(key: &str) -> &'static str {
    match key {
        "card_id" => "card_id",
        "title" => "title",
        "summary" => "summary",
        "did" => "did",
        "algorithm" => "algorithm",
        "signature_hex" => "signature_hex",
        "mailbox_id" => "mailbox_id",
        "ephemeral_pub_key" => "ephemeral_pub_key",
        "mls_ciphertext" => "mls_ciphertext",
        "ttl_seconds" => "ttl_seconds",
        _ => "field",
    }
}

/// Extracts a top-level unsigned integer field from a flat JSON object.
pub(crate) fn uint_field(raw: &str, key: &str) -> Result<u32, BridgeError> {
    let needle = format!("\"{key}\"");
    let mut cursor = raw
        .find(needle.as_str())
        .ok_or(BridgeError::MissingField(field_name(key)))?;
    cursor += needle.len();
    let rest = raw[cursor..].trim_start();
    let after_colon = rest.strip_prefix(':').ok_or(BridgeError::MalformedJson)?;
    let digits: String = after_colon
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return Err(BridgeError::MalformedJson);
    }
    digits
        .parse::<u32>()
        .map_err(|_| BridgeError::InvalidField(field_name(key)))
}
