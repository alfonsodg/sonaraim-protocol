//! JSON bridge backing the WebAssembly/TypeScript wire-codec bindings.
//!
//! The pure-Rust functions here are the single source of truth for the
//! web/mobile contract: JSON in, wire-frame hex out (and back), canonical JCS
//! bytes, card verification, and the pinned interop vector. The `wasm`
//! cargo feature adds thin `wasm-bindgen` wrappers over these exact
//! functions, so native tests and the compiled `.wasm` module verify the
//! same `tests/vectors/v1.json` vectors as `node
//! scripts/verify-vectors.mjs`. Native builds gain no new dependencies.

use crate::wire::WireError;
use std::error::Error;
use std::fmt;

/// Errors returned by the JSON bridge (mirrored to JS as thrown `Error`s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// Input was not an object with string fields the bridge understands.
    MalformedJson,
    /// A required object field was absent.
    MissingField(&'static str),
    /// A field value failed validation (bad DID, URI, TTL, component kind).
    InvalidField(&'static str),
    /// Hex payload was not valid lowercase hexadecimal.
    InvalidHex,
    /// The binary wire codec rejected the frame.
    Wire(WireError),
    /// Card structural validation failed.
    InvalidCard(&'static str),
    /// Ed25519 signature check failed or the key/signature was malformed.
    InvalidSignature,
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedJson => write!(f, "bridge input must be a JSON object"),
            Self::MissingField(field) => write!(f, "bridge input missing field: {field}"),
            Self::InvalidField(field) => write!(f, "bridge field invalid: {field}"),
            Self::InvalidHex => write!(f, "bridge hex payload invalid"),
            Self::Wire(err) => write!(f, "bridge wire codec error: {err}"),
            Self::InvalidCard(detail) => write!(f, "bridge card invalid: {detail}"),
            Self::InvalidSignature => write!(f, "bridge signature invalid"),
        }
    }
}

impl Error for BridgeError {}

impl From<WireError> for BridgeError {
    fn from(err: WireError) -> Self {
        Self::Wire(err)
    }
}
