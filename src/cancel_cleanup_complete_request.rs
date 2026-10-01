use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA,
    EndpointRevocationExecutionCancelCleanupCompleteRequestV1, SignedAuthorityExchangeV1,
    decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict,
    validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1, random_id};

pub(super) fn build(
    value: &CancelRecordV1,
    exchange: &SignedAuthorityExchangeV1,
) -> Result<EndpointRevocationExecutionCancelCleanupCompleteRequestV1, AgentError> {
    let finalize = value
        .cancel_finalize_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let cleanup = value
        .cancellation_cleanup
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = EndpointRevocationExecutionCancelCleanupCompleteRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_CLEANUP_COMPLETE_REQUEST_SCHEMA.into(),
        request_id: random_id::create("revocation-execution-cancel-cleanup-complete")?,
        operation_id: value.operation_id.clone(),
        cancel_finalize_request: Box::new(finalize.clone()),
        cleanup: Box::new(cleanup.clone()),
        acknowledge_exchange: exchange.clone(),
    };
    let wire = serde_json::to_vec(&request).map_err(|_| AgentError::RequestInvalid)?;
    let decoded =
        decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(&wire)
            .map_err(|_| AgentError::RequestInvalid)?;
    validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance(
        &decoded, cleanup,
    )
    .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == request)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
