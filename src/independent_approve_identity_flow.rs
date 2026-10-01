use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    independent_approve_state_types::IndependentApproveResume, replay::DurableSecurityState,
};

pub(super) fn finish<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking = crate::independent_approve_state_phase::finish_invoking(state, &operation, now)?;
    let response = identity.invoke_finish_fresh_uv(
        &config.0,
        &invoking.approval.finish_request,
        &invoking.approval.browser_request.command,
        now,
    );
    let response = match response {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::finish_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::finish_unknown(state, &operation, now)?;
    crate::source_approve_verify::finish(
        &config.0,
        &value.approval.browser_request,
        &value.selected_begin,
        &response,
        now,
    )?;
    crate::independent_approve_state_identity::finish_received(state, &operation, &response, now)
}

pub(super) fn prepare_current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = &value.approval.operation_id;
    let request = identity.prepare_current_identity(&config.0, now)?;
    crate::independent_approve_state_identity::current_prepared(state, operation, &request, now)
}

pub(super) fn current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::independent_approve_state_phase::current_invoking(state, &operation, now)?;
    let request = invoking
        .approval
        .current_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let response = identity.invoke_current_identity(&config.0, request, now);
    let response = match response {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::current_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::current_unknown(state, &operation, now)?;
    crate::target_approve_current::verify(config, state, &response, now)?;
    crate::independent_approve_state_identity::current_received(state, &operation, &response, now)
}

pub(super) fn observe<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::independent_approve_state_phase::observe_invoking(state, &operation, now)?;
    let current = invoking
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if let Err(error) = crate::core_identity::verify_and_observe(config, state, current, now) {
        crate::independent_approve_state_phase::observe_unknown(state, &operation, now)?;
        return Err(error);
    }
    let unknown = crate::independent_approve_state_phase::observe_unknown(state, &operation, now)?;
    crate::independent_approve_verify::actor(&config.0, &unknown, now)?;
    let begun = unknown
        .lookup
        .response
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let current = unknown
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = identity.prepare_independent_revocation_approval(
        &config.0,
        &unknown.lookup.response.prepared,
        begun,
        current,
        now,
    )?;
    crate::independent_approve_state_identity::observation_complete(
        &config.0, state, &operation, &request, now,
    )
}
