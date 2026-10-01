use crowsi_credential_authority_contracts::{
    CredentialClassV2, ManagementCredentialV2, ManagementDeviceV2, ManagementLifecycleV2,
    ManagementSessionV2, ManagementSnapshotV2,
};
use ihat_identity_assertion_contracts::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, DEVICE_IDENTITY_ASSERTION_SCHEMA,
    DeviceIdentityAssertionV1, DevicePostureV1, IdentityEvidenceMetadata, RevocationEpochsV1,
};

pub(super) fn identity() -> IdentityEvidenceMetadata {
    let assertion = DeviceIdentityAssertionV1 {
        schema: DEVICE_IDENTITY_ASSERTION_SCHEMA.into(),
        issuer: "issuer".into(),
        audience: "audience".into(),
        service_id: "service".into(),
        pairwise_subject: "psu_subject".into(),
        device_id: "device-a".into(),
        device_proof_key_ref: "proof-a".into(),
        session_ref: "session-a".into(),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 1,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 1,
            service: 1,
            device: 1,
            session: 1,
        },
        issued_at_epoch_s: 99,
        expires_at_epoch_s: 130,
        nonce: "identity-nonce".into(),
        key_id: "identity-key".into(),
        signature: "signature".into(),
    };
    IdentityEvidenceMetadata {
        current_status: CurrentDeviceStatusV1 {
            schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
            issuer: assertion.issuer.clone(),
            audience: assertion.audience.clone(),
            service_id: assertion.service_id.clone(),
            pairwise_subject: assertion.pairwise_subject.clone(),
            device_id: assertion.device_id.clone(),
            device_proof_key_ref: assertion.device_proof_key_ref.clone(),
            session_ref: assertion.session_ref.clone(),
            device_posture: assertion.device_posture.clone(),
            revocation_epochs: assertion.revocation_epochs.clone(),
            issued_at_epoch_s: assertion.issued_at_epoch_s,
            expires_at_epoch_s: assertion.expires_at_epoch_s,
            nonce: assertion.nonce.clone(),
            key_id: "status-key".into(),
            signature: "signature".into(),
        },
        assertion,
    }
}

pub(super) fn snapshot() -> ManagementSnapshotV2 {
    ManagementSnapshotV2 {
        devices: vec![device("device-a", 1), device("device-b", 2)],
        sessions: vec![
            session("session-a", "device-a", 1, ManagementLifecycleV2::Active),
            session("session-b1", "device-b", 1, ManagementLifecycleV2::Active),
            session("session-b2", "device-b", 2, ManagementLifecycleV2::Active),
            session("session-b3", "device-b", 3, ManagementLifecycleV2::Revoked),
        ],
        credentials: vec![ManagementCredentialV2 {
            credential_ref: "credential-a".into(),
            provider: "service".into(),
            class: CredentialClassV2::OperationOnly,
            revision: 1,
            status: ManagementLifecycleV2::Active,
            assigned_device_refs: vec!["device-a".into()],
            scopes: vec!["read".into()],
            created_at_rfc3339: time().into(),
            updated_at_rfc3339: time().into(),
        }],
        pending_operations: vec![],
    }
}

fn device(reference: &str, epoch: u64) -> ManagementDeviceV2 {
    ManagementDeviceV2 {
        device_ref: reference.into(),
        status: ManagementLifecycleV2::Active,
        device_revocation_epoch: epoch,
        posture_revision: 1,
        session_refs: vec![],
        created_at_rfc3339: time().into(),
        updated_at_rfc3339: time().into(),
    }
}

fn session(
    reference: &str,
    device: &str,
    epoch: u64,
    status: ManagementLifecycleV2,
) -> ManagementSessionV2 {
    ManagementSessionV2 {
        session_ref: reference.into(),
        device_ref: device.into(),
        status,
        session_revocation_epoch: epoch,
        issued_at_rfc3339: time().into(),
        expires_at_rfc3339: "2031-01-01T00:00:00Z".into(),
    }
}

fn time() -> &'static str {
    "2030-01-01T00:00:00Z"
}
