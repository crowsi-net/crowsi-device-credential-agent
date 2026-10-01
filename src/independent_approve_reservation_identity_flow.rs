use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    independent_approve_state_types::IndependentApproveResume, replay::DurableSecurityState,
};

pub(super) fn prepare<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let request = identity.prepare_current_identity(&config.0, now)?;
    crate::independent_approve_state_reservation_identity::prepared(
        state,
        &value.approval.operation_id,
        &request,
        now,
    )
}

pub(super) fn invoke<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking = crate::independent_approve_state_phase::reservation_current_invoking(
        state, &operation, now,
    )?;
    let request = invoking
        .approval
        .reservation_current_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let response = identity.invoke_current_identity(&config.0, request, now);
    let response = match response {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::reservation_current_unknown(
                state, &operation, now,
            )?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::reservation_current_unknown(state, &operation, now)?;
    crate::target_approve_current::verify(config, state, &response, now)?;
    crate::independent_approve_state_reservation_identity::received(
        state, &operation, &response, now,
    )
}

pub(super) fn observe<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking = crate::independent_approve_state_phase::reservation_observe_invoking(
        state, &operation, now,
    )?;
    let current = invoking
        .approval
        .reservation_current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if let Err(error) = crate::core_identity::verify_and_observe(config, state, current, now) {
        crate::independent_approve_state_phase::reservation_observe_unknown(
            state, &operation, now,
        )?;
        return Err(error);
    }
    let unknown = crate::independent_approve_state_phase::reservation_observe_unknown(
        state, &operation, now,
    )?;
    let final_request = crate::independent_approve_final_flow::skeleton(identity, &unknown)?;
    let reserve = crate::independent_approve_execution_reserve_request::build(
        &unknown,
        crate::random_id::create("revocation-execution-reserve")?,
        final_request,
    )?;
    crate::independent_approve_state_reservation_identity::observation_complete(
        state, &operation, &reserve, now,
    )
}
