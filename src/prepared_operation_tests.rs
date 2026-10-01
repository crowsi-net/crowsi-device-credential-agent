use crowsi_credential_authority_contracts::ManagementIntentV2;

use crate::{
    AgentError, prepared_operation_revocation, prepared_operation_snapshot,
    prepared_operation_test_support::{identity, snapshot},
};

#[test]
fn revocation_policy_is_derived_only_from_verified_snapshot_and_signed_configuration() {
    let identity = identity();
    let snapshot = snapshot();
    let intent = device_revocation();
    let value = prepared_operation_revocation::build(
        &snapshot,
        &intent,
        &identity,
        "finalizer",
        "approval-c",
    )
    .expect("policy")
    .expect("revocation");
    assert_eq!(value.target_device_ref, "device-b");
    assert_eq!(value.expected_revoked_session_count, Some(2));
    assert_eq!(
        value.required_approval_authority_ref.as_deref(),
        Some("approval-c")
    );
    assert_eq!(value.finalization_authority_id, "finalizer");
}

#[test]
fn same_device_session_revocation_never_invents_an_independent_approval() {
    let identity = identity();
    let snapshot = snapshot();
    let intent = ManagementIntentV2::SessionRevocation {
        service_id: "service".into(),
        target_session_ref: "session-a".into(),
        expected_session_revocation_epoch: 1,
        expected_snapshot_revision: 7,
        nonce: "browser-nonce".into(),
    };
    let value = prepared_operation_revocation::build(
        &snapshot,
        &intent,
        &identity,
        "finalizer",
        "approval-c",
    )
    .expect("policy")
    .expect("revocation");
    assert_eq!(value.target_device_ref, "device-a");
    assert_eq!(value.required_approval_authority_ref, None);
    assert_eq!(value.expected_revoked_session_count, None);
}

#[test]
fn stale_snapshot_epoch_or_unassigned_transfer_credential_fails_closed() {
    let identity = identity();
    let snapshot = snapshot();
    assert_eq!(
        prepared_operation_snapshot::validate(&snapshot, 6, &device_revocation(), &identity),
        Err(AgentError::AuthorityRollback)
    );
    let transfer = ManagementIntentV2::DeviceTransfer {
        service_id: "service".into(),
        target_device_ref: "device-b".into(),
        credential_refs: vec!["missing".into()],
        expected_snapshot_revision: 7,
        nonce: "browser-nonce".into(),
    };
    assert_eq!(
        prepared_operation_snapshot::validate(&snapshot, 7, &transfer, &identity),
        Err(AgentError::RequestInvalid)
    );
}

fn device_revocation() -> ManagementIntentV2 {
    ManagementIntentV2::DeviceRevocation {
        service_id: "service".into(),
        target_device_ref: "device-b".into(),
        expected_device_revocation_epoch: 2,
        expected_snapshot_revision: 7,
        nonce: "browser-nonce".into(),
    }
}
