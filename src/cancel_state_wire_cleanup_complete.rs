use crowsi_credential_authority_contracts::{
    decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict,
    decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict,
    validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance,
    verify_endpoint_revocation_execution_cancellation_cleanup_complete_historic,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1};

pub(super) fn exact(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(request) = value.cleanup_complete_request.as_ref() else {
        return value
            .cleanup_complete_response
            .is_none()
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded =
        decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(&wire)
            .map_err(|_| AgentError::AuthorityRollback)?;
    validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance(
        &decoded,
        &decoded.cleanup,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    if decoded != *request || decoded.operation_id != value.operation_id {
        return Err(AgentError::AuthorityRollback);
    }
    response(value, &decoded)
}

fn response(
    value: &CancelRecordV1,
    request: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<(), AgentError> {
    let Some(response) = value.cleanup_complete_response.as_ref() else {
        return value
            .cleanup_complete_trust
            .is_none()
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    let wire = serde_json::to_vec(response).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let pin = value
        .cleanup_complete_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let acknowledge = value
        .cleanup_response_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    verify_endpoint_revocation_execution_cancellation_cleanup_complete_historic(
        &decoded,
        request,
        &request.cleanup,
        &pin.peer_device_ref,
        &crate::cancel_cleanup_complete_trust::historic(pin, acknowledge),
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    (decoded == *response)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
