use crowsi_credential_authority_contracts::*;

use crate::management_support::{NOW, SESSION};

const SOURCE_SESSION: &str =
    "sref_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn request(id: &str, operation: &str) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::ApprovalOptions {
            operation_id: operation.into(),
            expected_state_revision: 3,
        },
    }
}

pub fn prepared() -> EndpointPreparedOperationV2 {
    let mut value = EndpointPreparedOperationV2 {
        operation_id: String::new(),
        origin_command_digest_sha256: "ac".repeat(32),
        source_device_ref: "device-b".into(),
        source_session_ref: SOURCE_SESSION.into(),
        pairwise_subject: "psu_pairwise-a".into(),
        opaque_owner_ref: "psa_owner_0000000000000001".into(),
        source_identity_nonce: "source-b-identity-nonce".into(),
        nonce: "prepared-revocation-nonce".into(),
        issued_at_epoch_s: NOW - 2,
        expires_at_epoch_s: NOW + 200,
        intent: ManagementIntentV2::DeviceRevocation {
            service_id: "service-a".into(),
            target_device_ref: "device-c".into(),
            expected_device_revocation_epoch: 1,
            expected_snapshot_revision: 1,
            nonce: "device-revocation-nonce".into(),
        },
        revocation: Some(RevocationRequirementsV2 {
            target_device_ref: "device-c".into(),
            required_approval_authority_ref: Some("independent-authority-c".into()),
            finalization_authority_id: "identity-authority".into(),
            expected_revoked_session_count: Some(2),
        }),
    };
    value.operation_id = endpoint_operation_id(&value).expect("operation id");
    value
}

pub fn lookup_request(wires: &[Vec<u8>]) -> EndpointPreparedLookupRequestV1 {
    wires
        .iter()
        .find_map(|wire| decode_endpoint_prepared_lookup_request_strict(wire).ok())
        .expect("approval lookup request")
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
        operation: awaiting_approval(&prepared),
        revocation_begin_exchange: Some(revocation_begin(&prepared)),
        pre_final_acceptance_request_sha256: None,
        prepared,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 14,
        key_id: "management-key".into(),
        signature: String::new(),
    }
}

include!("approval_options_support_begin.rs");

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
    .expect("verified approval lookup response");
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
    let ihat_identity_assertion_contracts::ResponseOutcome::Committed {
        result: ihat_identity_assertion_contracts::AuthorityResult::FreshUvBegun(options),
    } = uv_options.response.outcome
    else {
        panic!("fresh uv begun")
    };
    let mut operation = awaiting_approval(&prepared);
    operation.state = ManagementOperationState::AwaitingApprovalUv;
    operation.state_revision = 4;
    operation.actor.required_actor_device_ref = Some("device-a".into());
    operation.actor.required_approval_authority_ref = None;
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

include!("approval_options_support_operation.rs");
