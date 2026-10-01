use crowsi_credential_authority_contracts::*;

use crate::management_support::{NOW, SESSION};

pub fn request(id: &str, operation: &ManagementOperationV2) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::Cancel {
            operation_id: operation.operation_id.clone(),
            expected_state_revision: operation.state_revision,
        },
    }
}

pub fn prepared(expires: u64) -> EndpointPreparedOperationV2 {
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "ae".repeat(32),
        source_device_ref: "device-a".into(),
        source_session_ref: SESSION.into(),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "psa_owner_0000000000000001".into(),
        source_identity_nonce: "historic-source-nonce".into(),
        nonce: "cancel-prepared-nonce".into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: expires,
        intent: ManagementIntentV2::DeviceTransfer {
            service_id: "service-a".into(),
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_snapshot_revision: 1,
            nonce: "cancel-transfer-nonce".into(),
        },
        revocation: None,
    };
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    value
}

pub fn operation(prepared: &EndpointPreparedOperationV2) -> ManagementOperationV2 {
    ManagementOperationV2 {
        operation_id: prepared.operation_id.clone(),
        kind: ManagementOperationKind::DeviceTransfer,
        intent_digest_sha256: prepared.origin_command_digest_sha256.clone(),
        state: ManagementOperationState::AwaitingTarget,
        state_revision: 2,
        created_at_epoch_s: prepared.issued_at_epoch_s,
        expires_at_epoch_s: prepared.expires_at_epoch_s,
        source_device_ref: "device-a".into(),
        scope: ManagementOperationScopeV2::DeviceTransfer {
            target_device_ref: "device-b".into(),
            credential_refs: vec!["credential-a".into()],
            expected_source_device_revocation_epoch: 1,
        },
        actor: ActorRequirementV2 {
            role: RequiredActorRole::TargetDevice,
            required_actor_device_ref: Some("device-b".into()),
            required_approval_authority_ref: None,
            excluded_actor_device_refs: vec!["device-a".into()],
        },
        webauthn_options: None,
        reason: None,
        reconcile_digest: None,
    }
}

pub fn lookup(
    request: &EndpointPreparedLookupRequestV1,
    operation: ManagementOperationV2,
    prepared: EndpointPreparedOperationV2,
) -> EndpointPreparedLookupResponseV1 {
    lookup_at(request, operation, prepared, NOW)
}

pub fn lookup_with_digest(
    request: &EndpointPreparedLookupRequestV1,
    operation: ManagementOperationV2,
    prepared: EndpointPreparedOperationV2,
    digest: String,
) -> EndpointPreparedLookupResponseV1 {
    let mut value = lookup(request, operation, prepared);
    value.pre_final_acceptance_request_sha256 = Some(digest);
    value
}

pub fn lookup_at(
    request: &EndpointPreparedLookupRequestV1,
    operation: ManagementOperationV2,
    prepared: EndpointPreparedOperationV2,
    now: u64,
) -> EndpointPreparedLookupResponseV1 {
    EndpointPreparedLookupResponseV1 {
        schema: ENDPOINT_PREPARED_LOOKUP_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        request_digest_sha256: endpoint_prepared_lookup_request_digest(request).expect("digest"),
        actor_device_ref: "device-a".into(),
        actor_session_ref: SESSION.into(),
        subject_revocation_epoch: 1,
        service_revocation_epoch: 1,
        device_revocation_epoch: 1,
        session_revocation_epoch: 1,
        pre_final_acceptance_request_sha256: (operation.state
            == ManagementOperationState::AwaitingRevocationFinal)
            .then(|| "55".repeat(32)),
        operation,
        prepared,
        revocation_begin_exchange: None,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 20,
        key_id: "management-key".into(),
        signature: String::new(),
    }
}

pub fn lookup_request(wires: &[Vec<u8>]) -> EndpointPreparedLookupRequestV1 {
    wires
        .iter()
        .find_map(|wire| decode_endpoint_prepared_lookup_request_strict(wire).ok())
        .expect("cancel lookup")
}

pub fn cancelled(value: &ManagementOperationV2) -> ManagementOperationV2 {
    let mut value = value.clone();
    value.state = ManagementOperationState::Cancelled;
    value.state_revision += 1;
    value.actor = ActorRequirementV2 {
        role: RequiredActorRole::NoActor,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    };
    value.webauthn_options = None;
    value.reason = Some(ManagementReasonCode::OperationCancelled);
    value.reconcile_digest = None;
    value
}

include!("cancel_support_revocation.rs");
