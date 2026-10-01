use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::management_support::NOW;

pub const TARGET_SESSION: &str =
    "sref_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn request(id: &str) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::SourceOptions {
            intent: ManagementIntentV2::DeviceRevocation {
                service_id: "service-a".into(),
                target_device_ref: "device-b".into(),
                expected_device_revocation_epoch: 1,
                expected_snapshot_revision: 1,
                nonce: "source-revocation-nonce".into(),
            },
        },
    }
}

pub fn snapshot() -> ManagementSnapshotV2 {
    let mut value = crate::source_options_support::snapshot();
    value.devices[1].session_refs = vec![TARGET_SESSION.into()];
    value.sessions.push(ManagementSessionV2 {
        session_ref: TARGET_SESSION.into(),
        device_ref: "device-b".into(),
        status: ManagementLifecycleV2::Active,
        session_revocation_epoch: 1,
        issued_at_rfc3339: "2030-01-01T00:00:00Z".into(),
        expires_at_rfc3339: "2031-01-01T00:00:00Z".into(),
    });
    value.credentials.push(ManagementCredentialV2 {
        credential_ref: "credential-b".into(),
        provider: "service-a".into(),
        class: CredentialClassV2::OperationOnly,
        revision: 1,
        status: ManagementLifecycleV2::Active,
        assigned_device_refs: vec!["device-b".into()],
        scopes: vec!["revoke".into()],
        created_at_rfc3339: "2030-01-01T00:00:00Z".into(),
        updated_at_rfc3339: "2030-01-01T00:00:00Z".into(),
    });
    value
}

pub fn operation(
    prepared: &EndpointPreparedOperationV2,
    begin: &SignedAuthorityExchangeV1,
) -> ManagementOperationV2 {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        panic!("fresh uv options")
    };
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceRevocation,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingSourceUv,
        state_revision: 1,
        created_at_epoch_s: NOW,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: prepared.source_device_ref.clone(),
        scope: ManagementOperationScopeV2::DeviceRevocation {
            target_device_ref: "device-b".into(),
            expected_device_revocation_epoch: 1,
            revokes_session_refs: vec![TARGET_SESSION.into()],
            rotates_credential_refs: vec!["credential-b".into()],
            preserves_device_refs: vec!["device-a".into()],
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::SourceDevice,
            required_actor_device_ref: Some(prepared.source_device_ref.clone()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: Vec::new(),
        },
        webauthn_options: Some(WebAuthnOptionsV2 {
            attempt_id: options.attempt_id.clone(),
            challenge: options.challenge.clone(),
            rp_id: options.rp_id.clone(),
            origin: options.origin.clone(),
            credential_id: options.credential_id.clone(),
            timeout_ms: options.timeout_ms,
            expires_at_epoch_s: options.expires_at_epoch_s,
            command_binding_sha256: options.command_binding_sha256.clone(),
        }),
        reason: None,
        reconcile_digest: None,
    }
}

include!("source_revocation_support_approved.rs");
