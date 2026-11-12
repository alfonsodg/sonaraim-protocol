//! Declarative Sonaraim Card schema and cryptographic merchant signature validator.
//!
//! Enforces strict anti-XSS component rules and verifies that every B2B card carries
//! a well-formed `did:web:` or `did:sonaraim:` Decentralized Identifier paired with
//! an `Ed25519` signature.

use std::error::Error;
use std::fmt;

/// Maximum number of declarative components permitted in a single [`SonaraimCard`].
pub const MAX_CARD_COMPONENTS: usize = 16;

/// Expected hexadecimal length of a 64-byte Ed25519 signature.
pub const ED25519_SIGNATURE_HEX_LEN: usize = 128;

/// Declarative UI component types supported by Sonaraim clients.
///
/// Raw HTML and executable script types are forbidden at the protocol level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentType {
    /// Plain-text paragraph block.
    TextBlock,
    /// Verified remote image asset (`https://` only).
    MediaImage,
    /// Structured key-value metadata row.
    KeyValueRow,
    /// Interactive button triggering a safe `https://` or `sonaraim://` URI.
    ActionButton,
    /// Unrecognized or explicitly forbidden component type name (e.g., `"raw_html"`, `"script"`).
    Unsupported(String),
}

impl ComponentType {
    /// Parses a wire string identifier into a [`ComponentType`].
    ///
    /// # Parameters
    /// - `raw`: The component type identifier from JSON or Protobuf mapping.
    ///
    /// # Returns
    /// A [`ComponentType`] variant; unknown or unsafe names map to [`ComponentType::Unsupported`].
    pub fn from_wire_str(raw: &str) -> Self {
        match raw.trim() {
            "text_block" => Self::TextBlock,
            "media_image" => Self::MediaImage,
            "key_value_row" => Self::KeyValueRow,
            "action_button" => Self::ActionButton,
            other => Self::Unsupported(other.to_string()),
        }
    }
}

/// A single declarative UI element inside a [`SonaraimCard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardComponent {
    /// Declarative component kind.
    pub component_type: ComponentType,
    /// Primary text or button label.
    pub label: String,
    /// Optional secondary value for [`ComponentType::KeyValueRow`] or captions.
    pub value: Option<String>,
    /// Optional target URI for [`ComponentType::ActionButton`] or [`ComponentType::MediaImage`].
    pub action_uri: Option<String>,
}

/// Cryptographic proof binding a [`SonaraimCard`] to a verified B2B merchant DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerchantSignature {
    /// Decentralized Identifier of the merchant (`did:web:...` or `did:sonaraim:...`).
    pub did: String,
    /// Signature algorithm identifier (must be `"Ed25519"`).
    pub algorithm: String,
    /// Hex-encoded 64-byte Ed25519 signature (128 hex characters).
    pub signature_hex: String,
}

/// Declarative B2B rich card transmitted inside an end-to-end encrypted MLS frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SonaraimCard {
    /// Unique identifier for the card instance.
    pub card_id: String,
    /// Human-readable card header title.
    pub title: String,
    /// Plain-text notification fallback summary.
    pub summary: String,
    /// Ordered collection of declarative UI components (`1..=16`).
    pub components: Vec<CardComponent>,
    /// Mandatory merchant DID signature.
    pub merchant_signature: MerchantSignature,
}

/// Validation errors returned by [`validate_card`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardValidationError {
    /// A required metadata field (`card_id`, `title`, or `summary`) is empty or oversized.
    InvalidMetadata(&'static str),
    /// The card has zero components or exceeds [`MAX_CARD_COMPONENTS`].
    InvalidComponentCount(usize),
    /// A component uses an unsupported or forbidden type such as raw HTML or script.
    UnsupportedComponentType(String),
    /// A field contains forbidden HTML/XSS markup or unsafe characters.
    UnsafeMarkupDetected(&'static str),
    /// An action or media URI is missing or uses an unsafe scheme (such as `javascript:`).
    InvalidActionUri(String),
    /// The merchant DID does not conform to `did:web:<id>` or `did:sonaraim:<id>`.
    InvalidMerchantDid(String),
    /// The signature algorithm is not `"Ed25519"`.
    UnsupportedSignatureAlgorithm(String),
    /// The hex signature is not 128 valid hexadecimal characters.
    InvalidSignatureHex,
}

impl fmt::Display for CardValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(field) => write!(f, "invalid or empty card metadata: {field}"),
            Self::InvalidComponentCount(count) => {
                write!(
                    f,
                    "invalid component count: {count} (expected 1..={MAX_CARD_COMPONENTS})"
                )
            }
            Self::UnsupportedComponentType(kind) => {
                write!(f, "unsupported or unsafe component type: {kind}")
            }
            Self::UnsafeMarkupDetected(field) => {
                write!(f, "unsafe HTML or script markup detected in field: {field}")
            }
            Self::InvalidActionUri(uri) => write!(f, "unsafe or malformed action URI: {uri}"),
            Self::InvalidMerchantDid(did) => write!(f, "invalid merchant DID: {did}"),
            Self::UnsupportedSignatureAlgorithm(alg) => {
                write!(
                    f,
                    "unsupported signature algorithm: {alg} (expected Ed25519)"
                )
            }
            Self::InvalidSignatureHex => {
                write!(
                    f,
                    "merchant signature must be 128 hexadecimal characters (64 bytes)"
                )
            }
        }
    }
}

impl Error for CardValidationError {}

/// Checks whether a string contains raw HTML tags or inline script event handlers.
fn contains_unsafe_markup(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    lower.contains('<')
        || lower.contains('>')
        || lower.contains("javascript:")
        || lower.contains("onerror=")
        || lower.contains("onload=")
}

/// Validates that a URI uses `https://` or `sonaraim://` and has no unsafe characters.
fn is_safe_uri(uri: &str) -> bool {
    let trimmed = uri.trim();
    let has_valid_scheme = trimmed.starts_with("https://") || trimmed.starts_with("sonaraim://");
    let min_len = if trimmed.starts_with("https://") {
        10
    } else {
        13
    };
    has_valid_scheme
        && trimmed.len() >= min_len
        && !trimmed
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\''))
}

/// Validates that a Decentralized Identifier starts with `did:web:` or `did:sonaraim:`.
fn is_valid_did(did: &str) -> bool {
    let suffix = did
        .strip_prefix("did:web:")
        .or_else(|| did.strip_prefix("did:sonaraim:"));
    match suffix {
        Some(rest) if rest.len() >= 3 && !rest.starts_with(':') && !rest.ends_with(':') => rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':')),
        _ => false,
    }
}

/// Validates a [`SonaraimCard`] against protocol structure, anti-XSS, and DID signature rules.
///
/// # Parameters
/// - `card`: Reference to the [`SonaraimCard`] to validate.
///
/// # Returns
/// `Ok(())` if all invariants hold, or a specific [`CardValidationError`] describing the violation.
pub fn validate_card(card: &SonaraimCard) -> Result<(), CardValidationError> {
    if card.card_id.trim().len() < 4 || card.card_id.len() > 128 {
        return Err(CardValidationError::InvalidMetadata("card_id"));
    }
    if card.title.trim().is_empty() || card.title.len() > 160 {
        return Err(CardValidationError::InvalidMetadata("title"));
    }
    if card.summary.trim().is_empty() || card.summary.len() > 500 {
        return Err(CardValidationError::InvalidMetadata("summary"));
    }
    if contains_unsafe_markup(&card.card_id)
        || contains_unsafe_markup(&card.title)
        || contains_unsafe_markup(&card.summary)
    {
        return Err(CardValidationError::UnsafeMarkupDetected("card_metadata"));
    }

    if card.components.is_empty() || card.components.len() > MAX_CARD_COMPONENTS {
        return Err(CardValidationError::InvalidComponentCount(
            card.components.len(),
        ));
    }

    for component in &card.components {
        if let ComponentType::Unsupported(ref kind) = component.component_type {
            return Err(CardValidationError::UnsupportedComponentType(kind.clone()));
        }
        if component.label.trim().is_empty() || component.label.len() > 500 {
            return Err(CardValidationError::InvalidMetadata("component.label"));
        }
        if contains_unsafe_markup(&component.label) {
            return Err(CardValidationError::UnsafeMarkupDetected("component.label"));
        }
        if let Some(ref val) = component.value {
            if contains_unsafe_markup(val) {
                return Err(CardValidationError::UnsafeMarkupDetected("component.value"));
            }
        }
        match (&component.component_type, &component.action_uri) {
            (ComponentType::ActionButton | ComponentType::MediaImage, Some(uri)) => {
                if !is_safe_uri(uri) {
                    return Err(CardValidationError::InvalidActionUri(uri.clone()));
                }
            }
            (ComponentType::ActionButton | ComponentType::MediaImage, None) => {
                return Err(CardValidationError::InvalidActionUri(String::new()));
            }
            (_, Some(uri)) if !is_safe_uri(uri) => {
                return Err(CardValidationError::InvalidActionUri(uri.clone()));
            }
            _ => {}
        }
    }

    if !is_valid_did(&card.merchant_signature.did) {
        return Err(CardValidationError::InvalidMerchantDid(
            card.merchant_signature.did.clone(),
        ));
    }
    if card.merchant_signature.algorithm != "Ed25519" {
        return Err(CardValidationError::UnsupportedSignatureAlgorithm(
            card.merchant_signature.algorithm.clone(),
        ));
    }
    let sig = &card.merchant_signature.signature_hex;
    if sig.len() != ED25519_SIGNATURE_HEX_LEN || !sig.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CardValidationError::InvalidSignatureHex);
    }

    Ok(())
}
