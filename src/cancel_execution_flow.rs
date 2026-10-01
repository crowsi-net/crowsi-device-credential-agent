use crowsi_credential_authority_contracts::{
    decode_endpoint_revocation_execution_cancel_request_strict,
    decode_endpoint_revocation_execution_cancellation_strict,
    verify_endpoint_revocation_execution_cancellation_at,
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
    crate::cancel_state_phase::execution_cancel_invoking(state, &operation, now)?;
    let response = match transport.exchange("revocation-execution-cancel", &wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::cancel_state_phase::execution_cancel_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::cancel_state_phase::execution_cancel_unknown(state, &operation, now)?;
    let cancellation = decode_endpoint_revocation_execution_cancellation_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let pin = crate::cancel_central_trust::pin(config, now);
    verify_endpoint_revocation_execution_cancellation_at(
        &cancellation,
        &request,
        &pin.peer_device_ref,
        &crate::cancel_central_trust::cancellation_fresh(&pin, now),
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::cancel_state_execution_accept::persist(
        state,
        &operation,
        &response,
        &cancellation,
        pin,
        now,
    )
}

fn exact(
    value: &CancelRecordV1,
) -> Result<
    (
        Vec<u8>,
        crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelRequestV1,
    ),
    AgentError,
> {
    let request = value
        .execution_cancel_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancel_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    (decoded == **request)
        .then_some((wire, decoded))
        .ok_or(AgentError::AuthorityRollback)
}
