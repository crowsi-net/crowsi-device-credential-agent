use crowsi_credential_authority_contracts::{
    attach_revocation_cancellation_cleanup,
    decode_endpoint_revocation_execution_cancel_finalize_request_strict,
    decode_endpoint_revocation_execution_cancellation_cleanup_strict,
    verify_endpoint_revocation_execution_cancellation_cleanup_at,
};

use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelRecordV1, replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(super) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    value: Box<CancelRecordV1>,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    let operation = value.operation_id.clone();
    let (wire, request) = exact(&value)?;
    let cancellation = &request.cancellation;
    crate::cancel_state_phase::cancel_finalize_invoking(state, &operation, now)?;
    let response = match transport.exchange("revocation-execution-cancel-finalize", &wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::cancel_state_phase::cancel_finalize_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::cancel_state_phase::cancel_finalize_unknown(state, &operation, now)?;
    let cleanup = decode_endpoint_revocation_execution_cancellation_cleanup_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let pin = crate::cancel_central_trust::pin(config, now);
    verify_endpoint_revocation_execution_cancellation_cleanup_at(
        &cleanup,
        &request,
        cancellation,
        &pin.peer_device_ref,
        &crate::cancel_central_trust::cleanup_fresh(&pin, now),
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let acknowledge =
        attach_revocation_cancellation_cleanup(&cleanup.acknowledge_request, &cleanup)
            .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::cancel_state_cleanup_accept::persist(
        state,
        &operation,
        &response,
        &cleanup,
        pin,
        &acknowledge,
        now,
    )
}

fn exact(
    value: &CancelRecordV1,
) -> Result<
    (
        Vec<u8>,
        crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelFinalizeRequestV1,
    ),
    AgentError,
> {
    let request = value
        .cancel_finalize_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancel_finalize_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    (decoded == *request)
        .then_some((wire, decoded))
        .ok_or(AgentError::AuthorityRollback)
}
