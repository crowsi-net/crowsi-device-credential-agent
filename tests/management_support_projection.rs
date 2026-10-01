use crowsi_credential_authority_contracts::*;

use crate::management_support::{NOW, SESSION};

pub fn projection(request: &ManagementRequestV2, revision: u64) -> ManagementProjectionV2 {
    ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: format!("projection-{revision}"),
        request_id: request.request_id.clone(),
        command_digest_sha256: management_command_digest(request).expect("digest"),
        issuer: "crowsi-credential-authority".into(),
        audience: "endpoint-a".into(),
        service_id: "service-a".into(),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_account_ref: "psa_owner_0000000000000001".into(),
        current_device_ref: "device-a".into(),
        current_session_ref: SESSION.into(),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        device_posture_state: "compliant".into(),
        device_posture_revision: 1,
        device_proof_key_ref: "device-proof:sha256:device-a".into(),
        snapshot_revision: revision,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 30,
        body: ManagementProjectionBodyV2::Snapshot {
            snapshot: ManagementSnapshotV2 {
                devices: vec![],
                sessions: vec![],
                credentials: vec![],
                pending_operations: vec![],
            },
        },
        key_id: "management-key".into(),
        signature: String::new(),
    }
}
