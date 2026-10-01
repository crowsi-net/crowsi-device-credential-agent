use crowsi_credential_authority_contracts::{
    ENDPOINT_INDEPENDENT_REVOCATION_FINALIZE_REQUEST_SCHEMA,
    EndpointIndependentRevocationFinalizeRequestV1,
    decode_endpoint_independent_revocation_finalize_request_strict,
    endpoint_independent_revocation_pre_final_request_digest,
    validate_endpoint_independent_revocation_finalize_against_acceptance,
};
use sha2::{Digest, Sha256};

use crate::{AgentError, independent_approve_state_types::IndependentApproveResume};

pub(super) fn build(
    value: &IndependentApproveResume,
) -> Result<EndpointIndependentRevocationFinalizeRequestV1, AgentError> {
    let record = &value.approval;
    let pre_final = record
        .pre_final_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let reserve = record
        .execution_reserve_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let reservation = record
        .execution_reservation
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = EndpointIndependentRevocationFinalizeRequestV1 {
        schema: ENDPOINT_INDEPENDENT_REVOCATION_FINALIZE_REQUEST_SCHEMA.into(),
        request_id: request_id(&record.operation_id, &reservation.reservation_id),
        operation_id: record.operation_id.clone(),
        expected_state_revision: reservation.reserved_state_revision,
        pre_final_state_revision: reservation.pre_final_state_revision,
        reconcile_digest: reserve.reconcile_digest.clone(),
        approve_revocation_request: record.browser_request.clone(),
        prepared: value.lookup.response.prepared.clone(),
        pre_final_request_sha256: endpoint_independent_revocation_pre_final_request_digest(
            pre_final,
        )
        .map_err(|_| AgentError::RequestInvalid)?,
        accepted_identity_exchange: reserve.accepted_identity_exchange.clone(),
        begin_exchange: reserve.begin_exchange.clone(),
        approval_exchange: reserve
            .approval_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        execution_reservation_id: reservation.reservation_id.clone(),
        execution_reservation_token: reservation.token.clone(),
        final_revoke_exchange: record
            .final_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
    };
    validate_endpoint_independent_revocation_finalize_against_acceptance(
        &request,
        pre_final,
        reserve,
        reservation,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    strict(request)
}

fn request_id(operation: &str, reservation: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"CROWSI-INDEPENDENT-REVOCATION-FINALIZE-REQUEST-V1\0");
    for value in [operation, reservation] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn strict(
    value: EndpointIndependentRevocationFinalizeRequestV1,
) -> Result<EndpointIndependentRevocationFinalizeRequestV1, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_independent_revocation_finalize_request_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
