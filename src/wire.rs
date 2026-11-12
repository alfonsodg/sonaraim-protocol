//! Deterministic binary wire codec for Sonaraim envelopes and declarative cards.
//!
//! Produces length-prefixed frames aligned with `configs/proto/sonaraim.proto`
//! without panicking on truncated or malformed network input.

use crate::card::{CardComponent, ComponentType, MerchantSignature, SonaraimCard};
use crate::envelope::SealedEnvelope;
use std::error::Error;
use std::fmt;

/// Magic header identifying Sonaraim v1 binary wire frames.
const WIRE_MAGIC: &[u8; 4] = b"SNR1";

/// Errors returned during wire encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Input buffer ended prematurely while reading a field.
    TruncatedFrame,
    /// Frame header magic bytes did not match `SNR1`.
    InvalidMagic,
    /// String payload contained invalid UTF-8 bytes.
    InvalidUtf8,
    /// Field exceeded maximum allowed wire size.
    FieldTooLarge,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedFrame => write!(f, "truncated binary wire frame"),
            Self::InvalidMagic => write!(f, "invalid Sonaraim wire magic header"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 sequence in wire frame"),
            Self::FieldTooLarge => write!(f, "wire field exceeds maximum size"),
        }
    }
}

impl Error for WireError {}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), WireError> {
    let len = u32::try_from(bytes.len()).map_err(|_| WireError::FieldTooLarge)?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

fn read_bytes<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], WireError> {
    if input.len() < 4 {
        return Err(WireError::TruncatedFrame);
    }
    let (len_bytes, rest) = input.split_at(4);
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    if rest.len() < len {
        return Err(WireError::TruncatedFrame);
    }
    let (data, remaining) = rest.split_at(len);
    *input = remaining;
    Ok(data)
}

fn read_str(input: &mut &[u8]) -> Result<String, WireError> {
    let bytes = read_bytes(input)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)
}

/// Encodes a [`SealedEnvelope`] into a deterministic length-prefixed binary frame.
pub fn encode_envelope(env: &SealedEnvelope) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(WIRE_MAGIC);
    write_bytes(&mut buf, env.mailbox_id.as_bytes())?;
    write_bytes(&mut buf, &env.ephemeral_pub_key)?;
    write_bytes(&mut buf, &env.mls_ciphertext)?;
    buf.extend_from_slice(&env.ttl_seconds.to_be_bytes());
    Ok(buf)
}

/// Decodes a binary frame into a [`SealedEnvelope`].
pub fn decode_envelope(raw: &[u8]) -> Result<SealedEnvelope, WireError> {
    if raw.len() < 4 {
        return Err(WireError::TruncatedFrame);
    }
    let (magic, mut cursor) = raw.split_at(4);
    if magic != WIRE_MAGIC {
        return Err(WireError::InvalidMagic);
    }
    let mailbox_id = read_str(&mut cursor)?;
    let ephemeral_pub_key = read_bytes(&mut cursor)?.to_vec();
    let mls_ciphertext = read_bytes(&mut cursor)?.to_vec();
    if cursor.len() < 4 {
        return Err(WireError::TruncatedFrame);
    }
    let ttl_seconds = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    Ok(SealedEnvelope {
        mailbox_id,
        ephemeral_pub_key,
        mls_ciphertext,
        ttl_seconds,
    })
}

/// Encodes a [`SonaraimCard`] into a deterministic length-prefixed binary frame.
pub fn encode_card(card: &SonaraimCard) -> Result<Vec<u8>, WireError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(WIRE_MAGIC);
    write_bytes(&mut buf, card.card_id.as_bytes())?;
    write_bytes(&mut buf, card.title.as_bytes())?;
    write_bytes(&mut buf, card.summary.as_bytes())?;
    let count = u32::try_from(card.components.len()).map_err(|_| WireError::FieldTooLarge)?;
    buf.extend_from_slice(&count.to_be_bytes());
    for comp in &card.components {
        let kind = match &comp.component_type {
            ComponentType::TextBlock => "text_block",
            ComponentType::MediaImage => "media_image",
            ComponentType::KeyValueRow => "key_value_row",
            ComponentType::ActionButton => "action_button",
            ComponentType::Unsupported(s) => s.as_str(),
        };
        write_bytes(&mut buf, kind.as_bytes())?;
        write_bytes(&mut buf, comp.label.as_bytes())?;
        write_bytes(&mut buf, comp.value.as_deref().unwrap_or("").as_bytes())?;
        write_bytes(
            &mut buf,
            comp.action_uri.as_deref().unwrap_or("").as_bytes(),
        )?;
    }
    write_bytes(&mut buf, card.merchant_signature.did.as_bytes())?;
    write_bytes(&mut buf, card.merchant_signature.algorithm.as_bytes())?;
    write_bytes(&mut buf, card.merchant_signature.signature_hex.as_bytes())?;
    Ok(buf)
}

/// Decodes a binary frame into a [`SonaraimCard`].
pub fn decode_card(raw: &[u8]) -> Result<SonaraimCard, WireError> {
    if raw.len() < 4 {
        return Err(WireError::TruncatedFrame);
    }
    let (magic, mut cursor) = raw.split_at(4);
    if magic != WIRE_MAGIC {
        return Err(WireError::InvalidMagic);
    }
    let card_id = read_str(&mut cursor)?;
    let title = read_str(&mut cursor)?;
    let summary = read_str(&mut cursor)?;
    if cursor.len() < 4 {
        return Err(WireError::TruncatedFrame);
    }
    let count = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
    cursor = &cursor[4..];
    let mut components = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let kind = read_str(&mut cursor)?;
        let label = read_str(&mut cursor)?;
        let val = read_str(&mut cursor)?;
        let uri = read_str(&mut cursor)?;
        components.push(CardComponent {
            component_type: ComponentType::from_wire_str(&kind),
            label,
            value: if val.is_empty() { None } else { Some(val) },
            action_uri: if uri.is_empty() { None } else { Some(uri) },
        });
    }
    let did = read_str(&mut cursor)?;
    let algorithm = read_str(&mut cursor)?;
    let signature_hex = read_str(&mut cursor)?;
    Ok(SonaraimCard {
        card_id,
        title,
        summary,
        components,
        merchant_signature: MerchantSignature {
            did,
            algorithm,
            signature_hex,
        },
    })
}
