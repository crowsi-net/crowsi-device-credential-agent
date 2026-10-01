use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_EXECUTION_RESERVE_REQUEST_SCHEMA,
    EndpointRevocationExecutionReserveRequestV1,
    decode_endpoint_revocation_execution_reserve_request_strict,
    endpoint_independent_revocation_pre_final_request_digest,
};

use crate::{AgentError, independent_approve_state_types::IndependentApproveResume};

pub(super) fn build(
    value: &IndependentApproveResume,
    request_id: String,
    final_request: ihat_identity_assertion_contracts::AuthorityRequestV1,
) -> Result<EndpointRevocationExecutionReserveRequestV1, AgentError> {
    let record = &value.approval;
    let pre_final = record
        .pre_final_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let projection = record
        .pre_final_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation { operation } =
        &projection.body
    else {
        return Err(AgentError::AuthorityRollback);
    };
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
        prepared: value.lookup.response.prepared.clone(),
        pre_final_acceptance_request_sha256:
            endpoint_independent_revocation_pre_final_request_digest(pre_final)
                .map_err(|_| AgentError::RequestInvalid)?,
        accepted_identity_exchange: record
            .current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        reservation_identity_exchange: record
            .reservation_current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        begin_exchange: crate::independent_approve_ceremony_context::begun(value)?.clone(),
        approval_exchange: record.approval_exchange.clone(),
        final_revoke_request: final_request,
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
