//! MLS (RFC 9420-style) group epoch key ratchet state machine.
//!
//! Ensures forward secrecy and post-compromise security by rotating the group
//! symmetric application secret on every membership addition, removal, or
//! emergency post-compromise recovery ratchet while maintaining a deterministic
//! SHA-256 transcript hash chain.

use crate::crypto::{aead_open, aead_seal, hmac_sha256, sha256, to_hex, CryptoError};
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
    /// Requested epoch does not match or has been purged.
    UnknownEpoch(u64),
    /// Underlying AEAD or entropy validation failure.
    Crypto(CryptoError),
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemberAlreadyPresent(did) => write!(f, "member already in group: {did}"),
            Self::NotAMember(did) => write!(f, "DID is not an active member: {did}"),
            Self::UnknownEpoch(ep) => write!(f, "unknown or purged MLS epoch: {ep}"),
            Self::Crypto(err) => write!(f, "MLS crypto error: {err}"),
        }
    }
}

impl Error for MlsError {}

/// Group state tracking active members, per-epoch ratcheted secrets, and cumulative transcript hash.
#[derive(Debug, Clone)]
pub struct MlsGroupState {
    group_id: String,
    epoch: u64,
    members: BTreeSet<String>,
    epoch_keys: HashMap<u64, [u8; 32]>,
    epoch_members: HashMap<u64, BTreeSet<String>>,
    transcript_hash: [u8; 32],
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

        let mut init_transcript = Vec::new();
        init_transcript.extend_from_slice(b"sonaraim-mls-transcript-v1:");
        init_transcript.extend_from_slice(group_id.as_bytes());
        init_transcript.push(b':');
        init_transcript.extend_from_slice(creator_did.as_bytes());
        let transcript_hash = sha256(&init_transcript);

        Self {
            group_id: group_id.to_string(),
            epoch: 0,
            members,
            epoch_keys,
            epoch_members,
            transcript_hash,
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

    /// Returns the lowercase hexadecimal SHA-256 cumulative transcript digest.
    pub fn transcript_digest_hex(&self) -> String {
        to_hex(&self.transcript_hash)
    }

    /// Checks whether `member_did` is currently in the group.
    pub fn is_member(&self, member_did: &str) -> bool {
        self.members.contains(member_did)
    }

    fn advance_epoch_with_bytes(&mut self, event_bytes: &[u8]) {
        let prev_key = self.current_epoch_key();
        self.epoch += 1;
        let mut context = Vec::with_capacity(self.group_id.len() + 8 + event_bytes.len());
        context.extend_from_slice(self.group_id.as_bytes());
        context.extend_from_slice(&self.epoch.to_be_bytes());
        context.extend_from_slice(event_bytes);
        let next_key = hmac_sha256(&prev_key, &context);
        self.epoch_keys.insert(self.epoch, next_key);
        self.epoch_members.insert(self.epoch, self.members.clone());

        let mut chain_input = Vec::with_capacity(32 + 8 + event_bytes.len());
        chain_input.extend_from_slice(&self.transcript_hash);
        chain_input.extend_from_slice(&self.epoch.to_be_bytes());
        chain_input.extend_from_slice(event_bytes);
        self.transcript_hash = sha256(&chain_input);
    }

    /// Adds a member and rotates the group key to a new epoch.
    pub fn add_member(&mut self, member_did: &str) -> Result<u64, MlsError> {
        if !self.members.insert(member_did.to_string()) {
            return Err(MlsError::MemberAlreadyPresent(member_did.to_string()));
        }
        let evt = format!("add:{member_did}");
        self.advance_epoch_with_bytes(evt.as_bytes());
        Ok(self.epoch)
    }

    /// Removes a member and rotates the group key so the removed member cannot decrypt future epochs.
    pub fn remove_member(&mut self, member_did: &str) -> Result<u64, MlsError> {
        if !self.members.remove(member_did) {
            return Err(MlsError::NotAMember(member_did.to_string()));
        }
        let evt = format!("remove:{member_did}");
        self.advance_epoch_with_bytes(evt.as_bytes());
        Ok(self.epoch)
    }

    /// Performs an emergency post-compromise key ratchet using `fresh_entropy`,
    /// advancing the epoch, updating the transcript hash chain, and optionally
    /// purging all prior epoch keys from memory.
    pub fn force_recovery_ratchet(
        &mut self,
        fresh_entropy: &[u8],
        purge_prior_epochs: bool,
    ) -> Result<u64, MlsError> {
        if fresh_entropy.is_empty() {
            return Err(MlsError::Crypto(CryptoError::MalformedInput(
                "fresh_entropy cannot be empty",
            )));
        }
        let mut evt = Vec::with_capacity(9 + fresh_entropy.len());
        evt.extend_from_slice(b"recovery:");
        evt.extend_from_slice(fresh_entropy);
        self.advance_epoch_with_bytes(&evt);

        if purge_prior_epochs {
            let current = self.epoch;
            self.epoch_keys.retain(|&ep, _| ep == current);
            self.epoch_members.retain(|&ep, _| ep == current);
        }

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
