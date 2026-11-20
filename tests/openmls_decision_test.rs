//! Decision lock for issue #15 (OpenMLS evaluation, 2026-11-20).
//!
//! Pins the guarantees that justified deferring OpenMLS adoption: the custom
//! Sonaraim Group Ratchet stays synchronous and DID-string keyed (no storage
//! provider, credential bundle, or Welcome/Commit flow), rotation is
//! deterministic across independent instances, and purged epochs stay
//! unrecoverable. Re-evaluation is tracked in issue #16.

use sonaraim_protocol::mls_group::{MlsError, MlsGroupState};

/// The group API is synchronous and DID-string keyed: no provider needed.
#[test]
fn group_ratchet_stays_synchronous_and_did_string_keyed() {
    let mut group = MlsGroupState::new("grp-decision-15", "did:sonaraim:alice");
    assert_eq!(group.epoch(), 0);
    assert!(group.is_member("did:sonaraim:alice"));
    assert_eq!(group.add_member("did:sonaraim:bob"), Ok(1));
    assert_eq!(group.remove_member("did:sonaraim:bob"), Ok(2));
    assert!(!group.is_member("did:sonaraim:bob"));
}

/// Independent instances running the same operations stay in lockstep.
#[test]
fn group_ratchet_transcript_stays_deterministic_across_instances() {
    let mut group_a = MlsGroupState::new("grp-decision-15", "did:sonaraim:alice");
    let mut group_b = MlsGroupState::new("grp-decision-15", "did:sonaraim:alice");
    assert_eq!(group_a.add_member("did:sonaraim:bob"), Ok(1));
    assert_eq!(group_b.add_member("did:sonaraim:bob"), Ok(1));
    assert_eq!(
        group_a.transcript_digest_hex(),
        group_b.transcript_digest_hex()
    );
    assert_eq!(
        group_a.current_epoch_key().expect("epoch key"),
        group_b.current_epoch_key().expect("epoch key")
    );
}

/// Purged epochs stay unrecoverable after an emergency recovery ratchet.
#[test]
fn group_ratchet_purged_epochs_stay_unknown() {
    let mut group = MlsGroupState::new("grp-decision-15", "did:sonaraim:alice");
    assert_eq!(group.add_member("did:sonaraim:bob"), Ok(1));
    let sealed = group
        .encrypt_application_msg(b"pre-compromise")
        .expect("encrypt epoch 1");
    assert_eq!(
        group.force_recovery_ratchet(b"decision-15-entropy", true),
        Ok(2)
    );
    assert_eq!(
        group.decrypt_application_msg(&sealed, 1, "did:sonaraim:bob"),
        Err(MlsError::UnknownEpoch(1))
    );
}
