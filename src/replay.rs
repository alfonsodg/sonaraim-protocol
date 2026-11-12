//! Sliding-window anti-replay guard for Sealed Sender envelopes and MLS epochs.
//!
//! Protects relay nodes, B2B gateways, and clients from duplicate envelope
//! re-submission and stale MLS group epoch downgrades with bounded memory usage.

use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::fmt;

/// Errors returned by [`ReplayWindow::check_and_record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The provided envelope identifier is empty or whitespace-only.
    EmptyEnvelopeId,
    /// The envelope identifier has already been observed within the active window.
    DuplicateEnvelope(String),
    /// The message MLS epoch is older than the highest observed epoch.
    StaleEpoch {
        /// Epoch number attached to the rejected message.
        provided: u64,
        /// Minimum acceptable epoch number tracked by the guard.
        min_required: u64,
    },
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEnvelopeId => write!(f, "envelope_id cannot be empty"),
            Self::DuplicateEnvelope(id) => write!(f, "duplicate envelope replay detected: {id}"),
            Self::StaleEpoch {
                provided,
                min_required,
            } => write!(
                f,
                "stale MLS epoch {provided} rejected (minimum required epoch: {min_required})"
            ),
        }
    }
}

impl Error for ReplayError {}

/// Bounded FIFO sliding window tracking observed envelope IDs and monotonic MLS epochs.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    capacity: usize,
    order: VecDeque<String>,
    seen: HashSet<String>,
    min_epoch: u64,
}

impl ReplayWindow {
    /// Creates a new [`ReplayWindow`] with the given maximum entry `capacity` (minimum `1`).
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            order: VecDeque::with_capacity(cap),
            seen: HashSet::with_capacity(cap),
            min_epoch: 0,
        }
    }

    /// Returns the maximum number of envelope IDs retained in the sliding window.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of envelope IDs currently stored in the window.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Returns `true` if no envelope IDs are currently recorded.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Returns the minimum acceptable MLS epoch observed so far.
    pub fn min_epoch(&self) -> u64 {
        self.min_epoch
    }

    /// Checks whether `envelope_id` is currently present in the sliding window.
    pub fn contains(&self, envelope_id: &str) -> bool {
        self.seen.contains(envelope_id.trim())
    }

    /// Validates that `envelope_id` is non-empty, not a duplicate, and that `epoch`
    /// is not lower than [`Self::min_epoch`], then records the envelope in FIFO order.
    pub fn check_and_record(&mut self, envelope_id: &str, epoch: u64) -> Result<(), ReplayError> {
        let trimmed = envelope_id.trim();
        if trimmed.is_empty() {
            return Err(ReplayError::EmptyEnvelopeId);
        }
        if self.seen.contains(trimmed) {
            return Err(ReplayError::DuplicateEnvelope(trimmed.to_string()));
        }
        if epoch < self.min_epoch {
            return Err(ReplayError::StaleEpoch {
                provided: epoch,
                min_required: self.min_epoch,
            });
        }

        if self.order.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }

        let owned = trimmed.to_string();
        self.seen.insert(owned.clone());
        self.order.push_back(owned);
        self.min_epoch = epoch;
        Ok(())
    }
}
