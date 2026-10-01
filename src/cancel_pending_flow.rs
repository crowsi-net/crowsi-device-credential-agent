use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelRecordV1,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
};

pub(super) fn invoke<I: IdentityEvidenceProvider>(
    _config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: Box<CancelRecordV1>,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    let operation = value.operation_id.clone();
    let cancellation = value
        .execution_cancellation
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = crowsi_credential_authority_contracts::attach_revocation_execution_cancellation(
        &cancellation.cancel_pending_request,
        cancellation,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    let trust = crate::cancel_response_trust::begin(&value)?;
    crate::cancel_state_phase::cancel_pending_invoking(state, &operation, now)?;
    let exchange = match identity.invoke_cancel_pending_revocation(&trust, &request, now) {
        Ok(exchange) => exchange,
        Err(error) => {
            crate::cancel_state_phase::cancel_pending_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::cancel_state_phase::cancel_pending_unknown(state, &operation, now)?;
    let finalize = crate::cancel_finalize_request::build(&value, &exchange, now)?;
    crate::cancel_state_pending_accept::persist(state, &operation, &exchange, &finalize, now)
}
