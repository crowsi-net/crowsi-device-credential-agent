use crowsi_credential_authority_contracts::{
    MANAGEMENT_PROJECTION_SCHEMA, ManagementDeviceV2, ManagementLifecycleV2,
    ManagementProjectionBodyV2, ManagementProjectionV2, ManagementSnapshotV2,
};
use std::os::unix::fs::MetadataExt;

use crate::{AgentError, management_state, replay::DurableLedger, replay_test_support::Fixture};

#[test]
fn signed_snapshot_cache_survives_other_views_and_rejects_substitution_or_expiry() {
    let fixture = Fixture::new_for("endpoint-security-state");
    let ledger = open(&fixture);
    let first = projection(4, 100);
    management_state::observe(&ledger, &first).expect("snapshot");
    let mut pending = first.clone();
    pending.projection_id = "pending".into();
    pending.request_id = "pending-request".into();
    pending.issued_at_epoch_s = 101;
    pending.expires_at_epoch_s = 131;
    pending.body = ManagementProjectionBodyV2::Pending { operations: vec![] };
    management_state::observe(&ledger, &pending).expect("same revision pending view");
    assert_eq!(
        management_state::snapshot(&ledger, 120)
            .expect("cached snapshot")
            .snapshot,
        snapshot("device-a"),
    );
    assert_eq!(
        management_state::snapshot(&ledger, 130),
        Err(AgentError::AuthorityUnavailable)
    );
    let mut substituted = projection(4, 102);
    substituted.body = ManagementProjectionBodyV2::Snapshot {
        snapshot: snapshot("device-b"),
    };
    assert_eq!(
        management_state::observe(&ledger, &substituted),
        Err(AgentError::AuthorityRollback)
    );
}

fn projection(revision: u64, issued: u64) -> ManagementProjectionV2 {
    ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: "snapshot".into(),
        request_id: "request".into(),
        command_digest_sha256: "a".repeat(64),
        issuer: "issuer".into(),
        audience: "endpoint".into(),
        service_id: "service".into(),
        pairwise_subject: "subject".into(),
        opaque_account_ref: "owner".into(),
        current_device_ref: "device-a".into(),
        current_session_ref: format!("sref_{}", "a".repeat(64)),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        device_posture_state: "compliant".into(),
        device_posture_revision: 1,
        device_proof_key_ref: "proof".into(),
        snapshot_revision: revision,
        issued_at_epoch_s: issued,
        expires_at_epoch_s: issued + 30,
        body: ManagementProjectionBodyV2::Snapshot {
            snapshot: snapshot("device-a"),
        },
        key_id: "key".into(),
        signature: "signature".into(),
    }
}

fn snapshot(device: &str) -> ManagementSnapshotV2 {
    let mut value = ManagementSnapshotV2 {
        devices: vec![],
        sessions: vec![],
        credentials: vec![],
        pending_operations: vec![],
    };
    value.devices.push(ManagementDeviceV2 {
        device_ref: device.into(),
        status: ManagementLifecycleV2::Active,
        device_revocation_epoch: 1,
        posture_revision: 1,
        session_refs: vec![],
        created_at_rfc3339: "2030-01-01T00:00:00Z".into(),
        updated_at_rfc3339: "2030-01-01T00:00:00Z".into(),
    });
    value
}

fn open(fixture: &Fixture) -> DurableLedger {
    DurableLedger::open(
        &fixture.state,
        &fixture.anchor,
        std::fs::metadata(&fixture.state).expect("metadata").uid(),
        "endpoint-a",
        1,
        "endpoint-security-state",
    )
    .expect("ledger")
}
