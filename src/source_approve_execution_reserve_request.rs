use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_EXECUTION_RESERVE_REQUEST_SCHEMA,
    EndpointRevocationExecutionReserveRequestV1,
    decode_endpoint_revocation_execution_reserve_request_strict,
    endpoint_management_phase_envelope_digest,
};

use crate::{AgentError, source_approve_state_types::SourceApproveResume};

pub(super) fn build(
    value: &SourceApproveResume,
    request_id: String,
) -> Result<EndpointRevocationExecutionReserveRequestV1, AgentError> {
    let record = &value.approval;
    let response = record
        .pre_final_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation { operation } =
        &response.body
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let envelope = record
        .central_envelope
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = EndpointRevocationExecutionReserveRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_RESERVE_REQUEST_SCHEMA.into(),
        request_id,
        operation_id: record.operation_id.clone(),
        expected_state_revision: operation.state_revision,
        reconcile_digest: operation
            .reconcile_digest
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        original_request: record.browser_request.clone(),
        prepared: value.source.prepared.clone(),
        pre_final_acceptance_request_sha256: endpoint_management_phase_envelope_digest(envelope)
            .map_err(|_| AgentError::AuthorityRollback)?,
        accepted_identity_exchange: record
            .current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        reservation_identity_exchange: record
            .reservation_current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        begin_exchange: record
            .revocation_begin_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        approval_exchange: None,
        final_revoke_request: record
            .revocation_final_request
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
    };
    strict(request)
}

fn strict(
    value: EndpointRevocationExecutionReserveRequestV1,
) -> Result<EndpointRevocationExecutionReserveRequestV1, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_revocation_execution_reserve_request_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
