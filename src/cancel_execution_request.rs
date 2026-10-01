use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA,
    EndpointRevocationExecutionCancelRequestV1, ManagementCommandV2, ManagementOperationState,
    ManagementProjectionBodyV2, ManagementProjectionV2,
    decode_endpoint_revocation_execution_cancel_request_strict,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1, random_id};

pub(super) fn build(
    value: &CancelRecordV1,
    response: &ManagementProjectionV2,
) -> Result<Option<EndpointRevocationExecutionCancelRequestV1>, AgentError> {
    let Some(digest) = value.pre_final_acceptance_request_sha256.as_ref() else {
        return Ok(None);
    };
    let lookup = value
        .lookup_response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let begin = value
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let envelope = value
        .central_envelope
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let ManagementCommandV2::Cancel {
        expected_state_revision,
        ..
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let ManagementProjectionBodyV2::Operation { operation } = &response.body else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let expected_cancelled = expected_state_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityResponseInvalid)?;
    if lookup.operation.state != ManagementOperationState::AwaitingRevocationFinal
        || operation.state != ManagementOperationState::Cancelled
        || operation.state_revision != expected_cancelled
        || lookup.pre_final_acceptance_request_sha256.as_ref() != Some(digest)
    {
        return Err(AgentError::AuthorityRollback);
    }
    let request = EndpointRevocationExecutionCancelRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_REQUEST_SCHEMA.into(),
        request_id: random_id::create("revocation-execution-cancel")?,
        operation_id: value.operation_id.clone(),
        expected_cancelled_state_revision: expected_cancelled,
        pre_final_acceptance_request_sha256: digest.clone(),
        cancel_envelope: envelope.as_ref().clone(),
        prepared: lookup.prepared.clone(),
        begin_exchange: begin.clone(),
    };
    let wire = serde_json::to_vec(&request).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_revocation_execution_cancel_request_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == request)
        .then_some(Some(decoded))
        .ok_or(AgentError::RequestInvalid)
}
