use crowsi_credential_authority_contracts::{
    ActorRequirementV2, EndpointPreparedOperationV2, MANAGEMENT_PROJECTION_SCHEMA,
    ManagementOperationKind, ManagementOperationScopeV2, ManagementOperationState,
    ManagementOperationV2, ManagementProjectionBodyV2, ManagementProjectionV2, RequiredActorRole,
    SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use super::super::super::webauthn;
use super::NOW;

pub(super) fn value(
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
) -> ManagementProjectionV2 {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        unreachable!()
    };
    ManagementProjectionV2 {
        schema: MANAGEMENT_PROJECTION_SCHEMA.into(),
        projection_id: "projection-a".into(),
        request_id: "browser-request".into(),
        command_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        issuer: "issuer".into(),
        audience: "audience".into(),
        service_id: "service".into(),
        pairwise_subject: prepared.pairwise_subject.clone(),
        opaque_account_ref: prepared.opaque_owner_ref.clone(),
        current_device_ref: prepared.source_device_ref.clone(),
        current_session_ref: prepared.source_session_ref.clone(),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        device_posture_state: "compliant".into(),
        device_posture_revision: 1,
        device_proof_key_ref: "proof-a".into(),
        snapshot_revision: 8,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 30,
        body: ManagementProjectionBodyV2::Operation {
            operation: operation(prepared, options),
        },
        key_id: "projection-key".into(),
        signature: "44".repeat(64),
    }
}

fn operation(
    prepared: &EndpointPreparedOperationV2,
    options: &ihat_identity_assertion_contracts::FreshUvRequestOptions,
) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceTransfer,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingSourceUv,
        state_revision: 1,
        created_at_epoch_s: NOW,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: prepared.source_device_ref.clone(),
        scope: ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_source_device_revocation_epoch: 1,
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::SourceDevice,
            required_actor_device_ref: Some(prepared.source_device_ref.clone()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
        webauthn_options: Some(webauthn(options)),
        reason: None,
        reconcile_digest: None,
    }
}
