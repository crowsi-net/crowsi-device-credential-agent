use crowsi_credential_authority_contracts::*;

use crate::{
    cancel_support,
    management_support::{Fixture, NOW},
};

pub fn request(id: &str, operation: &ManagementOperationV2) -> ManagementRequestV2 {
    ManagementRequestV2 {
        schema: MANAGEMENT_REQUEST_SCHEMA.into(),
        request_id: id.into(),
        command: ManagementCommandV2::Reconcile {
            operation_id: operation.operation_id.clone(),
            expected_state_revision: operation.state_revision,
            reconcile_digest: operation
                .reconcile_digest
                .clone()
                .expect("reconcile digest"),
        },
    }
}

pub fn unknown(prepared: &EndpointPreparedOperationV2, revision: u64) -> ManagementOperationV2 {
    let mut value = cancel_support::operation(prepared);
    value.state = ManagementOperationState::Unknown;
    value.state_revision = revision;
    value.actor = ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    };
    value.webauthn_options = None;
    value.reason = Some(ManagementReasonCode::ProviderOutcomeUnknown);
    value.reconcile_digest = Some("44".repeat(32));
    value
}

pub fn response(operation: &ManagementOperationV2) -> ManagementOperationV2 {
    let mut value = operation.clone();
    value.state_revision += 1;
    value
}

pub fn lookup(
    fixture: &Fixture,
    operation: ManagementOperationV2,
    prepared: EndpointPreparedOperationV2,
) {
    let request = lookup_request(&fixture.requests());
    fixture.respond_lookup(
        cancel_support::lookup(&request, operation, prepared),
        |_| {},
    );
}

pub fn lookup_request(wires: &[Vec<u8>]) -> EndpointPreparedLookupRequestV1 {
    wires
        .iter()
        .rev()
        .find_map(|wire| decode_endpoint_prepared_lookup_request_strict(wire).ok())
        .filter(|value| value.phase == EndpointPreparedLookupPhaseV1::Reconcile)
        .expect("reconcile lookup")
}

pub fn envelopes(fixture: &Fixture) -> Vec<Vec<u8>> {
    fixture
        .requests()
        .into_iter()
        .filter(|wire| {
            decode_endpoint_management_envelope_strict(wire).is_ok_and(|value| {
                matches!(
                    value.evidence,
                    EndpointManagementEvidenceV2::Reconcile { .. }
                )
            })
        })
        .collect()
}

pub fn prepare(
    id: &str,
    expires: u64,
) -> (
    Fixture,
    ManagementRequestV2,
    Vec<u8>,
    EndpointPreparedOperationV2,
    ManagementOperationV2,
) {
    let fixture = Fixture::new();
    let prepared = cancel_support::prepared(expires);
    let operation = unknown(&prepared, 5);
    let request = request(id, &operation);
    let wire = serde_json::to_vec(&request).expect("request");
    (fixture, request, wire, prepared, operation)
}

pub fn reach_central(id: &str) -> (Fixture, ManagementRequestV2, Vec<u8>, ManagementOperationV2) {
    let (fixture, request, wire, prepared, operation) = prepare(id, NOW + 200);
    assert!(fixture.core().handle(&wire, NOW).is_err());
    lookup(&fixture, operation.clone(), prepared);
    assert!(fixture.core().handle(&wire, NOW).is_err());
    (fixture, request, wire, operation)
}
