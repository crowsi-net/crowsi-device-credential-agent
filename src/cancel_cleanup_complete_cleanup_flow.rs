use crowsi_credential_authority_contracts::{
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
    let complete = value
        .cleanup_complete_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let finalize = &complete.cancel_finalize_request;
    let wire = serde_json::to_vec(finalize).map_err(|_| AgentError::AuthorityRollback)?;
    crate::cancel_state_phase::cleanup_complete_cleanup_invoking(state, &operation, now)?;
    let response = match transport.exchange("revocation-execution-cancel-finalize", &wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::cancel_state_phase::cleanup_complete_cleanup_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::cancel_state_phase::cleanup_complete_cleanup_unknown(state, &operation, now)?;
    let cleanup = decode_endpoint_revocation_execution_cancellation_cleanup_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let pin = crate::cancel_central_trust::pin(config, now);
    verify_endpoint_revocation_execution_cancellation_cleanup_at(
        &cleanup,
        finalize,
        &finalize.cancellation,
        &pin.peer_device_ref,
        &crate::cancel_central_trust::cleanup_fresh(&pin, now),
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::cancel_state_cleanup_complete_refresh::cleanup(state, &operation, &cleanup, pin, now)
}
