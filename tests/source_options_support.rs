use crowsi_credential_authority_contracts::*;
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::management_support::{NOW, SESSION};

pub fn request(id: &str) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::SourceOptions {
            intent: ManagementIntentV2::DeviceTransfer {
                service_id: "service-a".into(),
                target_device_ref: "device-b".into(),
                credential_refs: vec!["credential-a".into()],
                expected_snapshot_revision: 1,
                nonce: "source-options-nonce".into(),
            },
        },
    }
}

pub fn snapshot() -> ManagementSnapshotV2 {
    ManagementSnapshotV2 {
        devices: vec![
            device("device-a", vec![SESSION]),
            device("device-b", vec![]),
        ],
        sessions: vec![ManagementSessionV2 {
            session_ref: SESSION.into(),
            device_ref: "device-a".into(),
            status: ManagementLifecycleV2::Active,
            session_revocation_epoch: 1,
            issued_at_rfc3339: "2030-01-01T00:00:00Z".into(),
            expires_at_rfc3339: "2031-01-01T00:00:00Z".into(),
        }],
        credentials: vec![ManagementCredentialV2 {
            credential_ref: "credential-a".into(),
            provider: "service-a".into(),
            class: CredentialClassV2::OperationOnly,
            revision: 1,
            status: ManagementLifecycleV2::Active,
            assigned_device_refs: vec!["device-a".into()],
            scopes: vec!["transfer".into()],
            created_at_rfc3339: "2030-01-01T00:00:00Z".into(),
            updated_at_rfc3339: "2030-01-01T00:00:00Z".into(),
        }],
        pending_operations: Vec::new(),
    }
}

pub fn source_evidence(wire: &[u8]) -> (EndpointPreparedOperationV2, SignedAuthorityExchangeV1) {
    let envelope = decode_endpoint_management_envelope_strict(wire).expect("source envelope");
    let EndpointManagementEvidenceV2::SourceOptions {
        prepared,
        uv_options,
        ..
    } = envelope.evidence
    else {
        panic!("source options evidence")
    };
    (prepared, uv_options)
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
        kind: ManagementOperationKind::DeviceTransfer,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingSourceUv,
        state_revision: 1,
        created_at_epoch_s: NOW,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: "device-a".into(),
        scope: ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_source_device_revocation_epoch: 1,
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::SourceDevice,
            required_actor_device_ref: Some("device-a".into()),
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

fn device(reference: &str, sessions: Vec<&str>) -> ManagementDeviceV2 {
    ManagementDeviceV2 {
        device_ref: reference.into(),
        status: ManagementLifecycleV2::Active,
        device_revocation_epoch: 1,
        posture_revision: 1,
        session_refs: sessions.into_iter().map(str::to_owned).collect(),
        created_at_rfc3339: "2030-01-01T00:00:00Z".into(),
        updated_at_rfc3339: "2030-01-01T00:00:00Z".into(),
    }
}
