//! MLS (RFC 9420-style) group epoch key ratchet state machine.
//!
//! Ensures forward secrecy and post-compromise security by rotating the group
//! symmetric application secret on every membership addition or removal.

use crate::crypto::{aead_open, aead_seal, hmac_sha256, CryptoError};
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;

/// Errors returned by [`MlsGroupState`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsError {
    /// Attempted to add a member that is already in the group.
    MemberAlreadyPresent(String),
    /// Attempted to remove or decrypt for a DID not in the group at that epoch.
    NotAMember(String),
    /// Requested epoch does not match or is unavailable.
    UnknownEpoch(u64),
    /// Underlying AEAD failure.
    Crypto(CryptoError),
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemberAlreadyPresent(did) => write!(f, "member already in group: {did}"),
            Self::NotAMember(did) => write!(f, "DID is not an active member: {did}"),
            Self::UnknownEpoch(ep) => write!(f, "unknown MLS epoch: {ep}"),
            Self::Crypto(err) => write!(f, "MLS crypto error: {err}"),
        }
    }
}

impl Error for MlsError {}

/// Group state tracking active members and per-epoch ratcheted secrets.
#[derive(Debug, Clone)]
pub struct MlsGroupState {
    group_id: String,
    epoch: u64,
    members: BTreeSet<String>,
    epoch_keys: HashMap<u64, [u8; 32]>,
    epoch_members: HashMap<u64, BTreeSet<String>>,
}

impl MlsGroupState {
    /// Creates a new MLS group at epoch `0` initialized by `creator_did`.
    pub fn new(group_id: &str, creator_did: &str) -> Self {
        let mut members = BTreeSet::new();
        members.insert(creator_did.to_string());
        let seed_key = hmac_sha256(group_id.as_bytes(), creator_did.as_bytes());
        let mut epoch_keys = HashMap::new();
        epoch_keys.insert(0, seed_key);
        let mut epoch_members = HashMap::new();
        epoch_members.insert(0, members.clone());
        Self {
            group_id: group_id.to_string(),
            epoch: 0,
            members,
            epoch_keys,
            epoch_members,
        }
    }

    /// Returns the current MLS epoch counter.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the 32-byte application secret for the current epoch.
    pub fn current_epoch_key(&self) -> [u8; 32] {
        self.epoch_keys
            .get(&self.epoch)
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// Checks whether `member_did` is currently in the group.
    pub fn is_member(&self, member_did: &str) -> bool {
        self.members.contains(member_did)
    }

    fn advance_epoch(&mut self, event: &str) {
        let prev_key = self.current_epoch_key();
        self.epoch += 1;
        let mut context = Vec::new();
        context.extend_from_slice(self.group_id.as_bytes());
        context.extend_from_slice(&self.epoch.to_be_bytes());
        context.extend_from_slice(event.as_bytes());
        let next_key = hmac_sha256(&prev_key, &context);
        self.epoch_keys.insert(self.epoch, next_key);
        self.epoch_members.insert(self.epoch, self.members.clone());
    }

    /// Adds a member and rotates the group key to a new epoch.
    pub fn add_member(&mut self, member_did: &str) -> Result<u64, MlsError> {
        if !self.members.insert(member_did.to_string()) {
            return Err(MlsError::MemberAlreadyPresent(member_did.to_string()));
        }
        self.advance_epoch(&format!("add:{member_did}"));
        Ok(self.epoch)
    }

    /// Removes a member and rotates the group key so the removed member cannot decrypt future epochs.
    pub fn remove_member(&mut self, member_did: &str) -> Result<u64, MlsError> {
        if !self.members.remove(member_did) {
            return Err(MlsError::NotAMember(member_did.to_string()));
        }
        self.advance_epoch(&format!("remove:{member_did}"));
        Ok(self.epoch)
    }

    /// Encrypts an application payload under the current epoch's ratcheted key.
    pub fn encrypt_application_msg(&self, plaintext: &[u8]) -> Result<Vec<u8>, MlsError> {
        let key = self
            .epoch_keys
            .get(&self.epoch)
            .ok_or(MlsError::UnknownEpoch(self.epoch))?;
        let aad = format!("{}:{}", self.group_id, self.epoch);
        Ok(aead_seal(key, aad.as_bytes(), plaintext))
    }

    /// Decrypts an application payload only if `requester_did` was a member at `msg_epoch`.
    pub fn decrypt_application_msg(
        &self,
        ciphertext: &[u8],
        msg_epoch: u64,
        requester_did: &str,
    ) -> Result<Vec<u8>, MlsError> {
        let allowed = self
            .epoch_members
            .get(&msg_epoch)
            .ok_or(MlsError::UnknownEpoch(msg_epoch))?;
        if !allowed.contains(requester_did) {
            return Err(MlsError::NotAMember(requester_did.to_string()));
        }
        let key = self
            .epoch_keys
            .get(&msg_epoch)
            .ok_or(MlsError::UnknownEpoch(msg_epoch))?;
        let aad = format!("{}:{}", self.group_id, msg_epoch);
        aead_open(key, aad.as_bytes(), ciphertext).map_err(MlsError::Crypto)
    }
}
