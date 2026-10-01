use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_approve_state_types::SourceApproveResume,
};

pub(super) fn invoke<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: SourceApproveResume,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::source_approve_state_phase::reservation_current_invoking(state, &operation, now)?;
    let request = invoking
        .approval
        .reservation_current_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let response = identity.invoke_current_identity(&config.0, request, now);
    let response = match response {
        Ok(value) => value,
        Err(error) => {
            crate::source_approve_state_phase::reservation_current_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::source_approve_state_phase::reservation_current_unknown(state, &operation, now)?;
    crate::target_approve_current::verify(config, state, &response, now)?;
    crate::source_approve_state_reservation_identity::received(state, &operation, &response, now)
}

pub(super) fn observe<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    _identity: &I,
    value: SourceApproveResume,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::source_approve_state_phase::reservation_observe_invoking(state, &operation, now)?;
    let current = invoking
        .approval
        .reservation_current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if let Err(error) = crate::core_identity::verify_and_observe(config, state, current, now) {
        crate::source_approve_state_phase::reservation_observe_unknown(state, &operation, now)?;
        return Err(error);
    }
    let unknown =
        crate::source_approve_state_phase::reservation_observe_unknown(state, &operation, now)?;
    let reserve = crate::source_approve_execution_reserve_request::build(
        &unknown,
        crate::random_id::create("revocation-execution-reserve")?,
    )?;
    crate::source_approve_state_reservation_identity::observation_complete(
        state, &operation, &reserve, now,
    )
}
