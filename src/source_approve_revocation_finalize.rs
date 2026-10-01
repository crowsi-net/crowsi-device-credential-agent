use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA, EndpointRevocationFinalizeRequestV1,
    ManagementOperationState, ManagementProjectionBodyV2, SignedAuthorityExchangeV1,
    decode_endpoint_revocation_finalize_request_strict, endpoint_management_phase_envelope_digest,
    validate_endpoint_revocation_finalize_against_acceptance,
};

use crate::{AgentError, source_approve_state_types::SourceApproveResume};

pub(crate) fn build(
    value: &SourceApproveResume,
    final_exchange: &SignedAuthorityExchangeV1,
) -> Result<EndpointRevocationFinalizeRequestV1, AgentError> {
    let record = &value.approval;
    let response = record
        .pre_final_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let ManagementProjectionBodyV2::Operation { operation } = &response.body else {
        return Err(AgentError::AuthorityRollback);
    };
    let reconcile_digest = operation
        .reconcile_digest
        .clone()
        .ok_or(AgentError::AuthorityRollback)?;
    let envelope = record
        .central_envelope
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
    if operation.state != ManagementOperationState::AwaitingRevocationFinal
        || final_exchange.response.issued_at_epoch_s < response.issued_at_epoch_s
    {
        return Err(AgentError::AuthorityRollback);
    }
    let pre_final_request_sha256 = endpoint_management_phase_envelope_digest(envelope)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let request = EndpointRevocationFinalizeRequestV1 {
        schema: ENDPOINT_REVOCATION_FINALIZE_REQUEST_SCHEMA.into(),
        request_id: record
            .revocation_finalize_request_id
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        operation_id: value.source.prepared.operation_id.clone(),
        expected_state_revision: reservation.reserved_state_revision,
        pre_final_state_revision: reservation.pre_final_state_revision,
        reconcile_digest,
        source_approve_request: record.browser_request.clone(),
        prepared: value.source.prepared.clone(),
        pre_final_request_sha256: pre_final_request_sha256.clone(),
        accepted_identity_exchange: record
            .current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        execution_reservation_id: reservation.reservation_id.clone(),
        execution_reservation_token: reservation.token.clone(),
        final_revoke_exchange: final_exchange.clone(),
    };
    validate_endpoint_revocation_finalize_against_acceptance(
        &request,
        &pre_final_request_sha256,
        record
            .revocation_begin_exchange
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?,
        reserve,
        reservation,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let wire = serde_json::to_vec(&request).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_revocation_finalize_request_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == request)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
