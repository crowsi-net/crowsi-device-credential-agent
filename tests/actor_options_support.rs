use crate::management_support::{NOW, SESSION};
use crowsi_credential_authority_contracts::*;
const SOURCE_SESSION: &str =
    "sref_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn request(id: &str, operation: &str) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::TargetOptions {
            operation_id: operation.into(),
            expected_state_revision: 2,
        },
    }
}

pub fn prepared() -> EndpointPreparedOperationV2 {
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "ab".repeat(32),
        source_device_ref: "device-b".into(),
        source_session_ref: SOURCE_SESSION.into(),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "psa_owner_0000000000000001".into(),
        source_identity_nonce: "source-identity-nonce".into(),
        nonce: "prepared-operation-nonce".into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 200,
        intent: ManagementIntentV2::DeviceTransfer {
            service_id: "service-a".into(),
            target_device_ref: "device-a".into(),
            credential_refs: vec!["credential-a".into()],
            expected_snapshot_revision: 1,
            nonce: "transfer-intent-nonce".into(),
        },
        revocation: None,
    };
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    value
}

pub fn lookup_request(wires: &[Vec<u8>]) -> EndpointPreparedLookupRequestV1 {
    wires
        .iter()
        .find_map(|wire| decode_endpoint_prepared_lookup_request_strict(wire).ok())
        .expect("lookup request")
}

pub fn lookup_response(
    request: &EndpointPreparedLookupRequestV1,
    prepared: EndpointPreparedOperationV2,
) -> EndpointPreparedLookupResponseV1 {
    EndpointPreparedLookupResponseV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_digest_sha256: endpoint_prepared_lookup_request_digest(request)
            .expect("lookup digest"),
        actor_device_ref: "device-a".into(),
        actor_session_ref: SESSION.into(),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        operation: awaiting_target(&prepared),
        prepared,
        revocation_begin_exchange: None,
        pre_final_acceptance_request_sha256: None,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 20,
        key_id: "management-key".into(),
        signature: String::new(),
    }
}

pub fn assert_lookup(
    request: &EndpointPreparedLookupRequestV1,
    value: &EndpointPreparedLookupResponseV1,
) {
    let wire = serde_json::to_vec(value).expect("lookup wire");
    decode_endpoint_prepared_lookup_response_strict(&wire).expect("strict lookup response");
    let key = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
    verify_endpoint_prepared_lookup_response_at(
        value,
        request,
        "management-key",
        &hex::encode(key.verifying_key().to_bytes()),
        NOW,
    )
    .expect("verified lookup response");
}

pub fn actor_operation(wire: &[u8]) -> ManagementOperationV2 {
    let envelope = decode_endpoint_management_envelope_strict(wire).expect("actor envelope");
    let EndpointManagementEvidenceV2::ActorOptions {
        prepared,
        uv_options,
        ..
    } = envelope.evidence
    else {
        panic!("actor options evidence")
    };
    let mut operation = awaiting_target(&prepared);
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::FreshUvBegun(options),
    } = uv_options.response.outcome
    else {
        panic!("fresh uv begun")
    };
    operation.state = ManagementOperationState::AwaitingTargetUv;
    operation.state_revision = 3;
    operation.webauthn_options = Some(WebAuthnOptionsV2 {
        attempt_id: options.attempt_id,
        challenge: options.challenge,
        rp_id: options.rp_id,
        origin: options.origin,
        credential_id: options.credential_id,
        timeout_ms: options.timeout_ms,
        expires_at_epoch_s: options.expires_at_epoch_s,
        command_binding_sha256: options.command_binding_sha256,
    });
    operation
}

fn awaiting_target(prepared: &EndpointPreparedOperationV2) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceTransfer,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingTarget,
        state_revision: 2,
        created_at_epoch_s: NOW - 1,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: prepared.source_device_ref.clone(),
        scope: ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: "device-a".into(),
            credential_refs: vec!["credential-a".into()],
            expected_source_device_revocation_epoch: 1,
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::TargetDevice,
            required_actor_device_ref: Some("device-a".into()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: vec![prepared.source_device_ref.clone()],
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: None,
    }
}
