use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, RevocationRequirementsV2,
    endpoint_operation_digest, endpoint_operation_id,
};
use ihat_identity_assertion_contracts::{
    AuthenticatorKindDto, FRESH_UV_SCHEMA, FreshUvV1, SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1,
    VerificationRole,
};

use crate::{AgentError, source_approve_revocation_request::SessionProofSigner};

pub(super) const NOW: u64 = 100;
pub(super) const TARGET_DIGEST: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

pub(super) struct FixtureSigner;

impl SessionProofSigner for FixtureSigner {
    fn sign_session_proof(
        &self,
        proof_id: &str,
        binding_sha256: &str,
        now: u64,
    ) -> Result<SignedEvidenceV1, AgentError> {
        Ok(SignedEvidenceV1 {
            schema: SIGNED_EVIDENCE_SCHEMA.into(),
            role: VerificationRole::SessionSender,
            proof_id: proof_id.into(),
            key_id: "session-sender-key".into(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now + 15,
            binding_sha256: binding_sha256.into(),
            signature: "22".repeat(64),
        })
    }
}

pub(super) fn device(target: &str) -> EndpointPreparedOperationV2 {
    prepared(
        ManagementIntentV2::DeviceRevocation {
            service_id: "service-a".into(),
            target_device_ref: target.into(),
            expected_device_revocation_epoch: 3,
            expected_snapshot_revision: 7,
            nonce: "intent-nonce".into(),
        },
        target,
        Some(2),
    )
}

pub(super) fn session(target_device: &str) -> EndpointPreparedOperationV2 {
    prepared(
        ManagementIntentV2::SessionRevocation {
            service_id: "service-a".into(),
            target_session_ref: "session-b".into(),
            expected_session_revocation_epoch: 5,
            expected_snapshot_revision: 7,
            nonce: "intent-nonce".into(),
        },
        target_device,
        None,
    )
}

pub(super) fn fresh(prepared: &EndpointPreparedOperationV2) -> FreshUvV1 {
    FreshUvV1 {
        schema: FRESH_UV_SCHEMA.into(),
        proof_id: "fresh-proof".into(),
        credential_id: "credential-a".into(),
        authenticator_key_fingerprint: "44".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 30,
        challenge: "challenge-a".into(),
        attempt_id: "uv-attempt-a".into(),
        identity_nonce: prepared.source_identity_nonce.clone(),
        source_device_id: prepared.source_device_ref.clone(),
        service_id: "service-a".into(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        session_ref: prepared.source_session_ref.clone(),
        operation_digest_sha256: endpoint_operation_digest(prepared).expect("operation digest"),
        subject_epoch: 1,
        service_epoch: 2,
        device_epoch: 3,
        session_epoch: 4,
        account_binding_sha256: "55".repeat(32),
        key_id: "fresh-uv-key".into(),
        signature: "11".repeat(64),
    }
}

fn prepared(
    intent: ManagementIntentV2,
    target_device: &str,
    session_count: Option<u64>,
) -> EndpointPreparedOperationV2 {
    let independent = target_device != "device-a";
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "aa".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: "session-a".into(),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "owner-a".into(),
        source_identity_nonce: "identity-nonce-a".into(),
        nonce: "prepared-nonce".into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 300,
        intent,
        revocation: Some(RevocationRequirementsV2 {
            target_device_ref: target_device.into(),
            required_approval_authority_ref: independent.then(|| "approval-authority".into()),
            finalization_authority_id: "runtime-revocation-key".into(),
            expected_revoked_session_count: session_count,
        }),
    };
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    value
}
