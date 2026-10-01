use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, target_approve_state_types::TargetApproveResume,
};

pub(super) fn finish<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: TargetApproveResume,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::target_approve_state_identity_phase::finish_invoking(state, &operation, now)?;
    let response = match identity.invoke_finish_fresh_uv(
        &config.0,
        &invoking.approval.finish_request,
        &invoking.approval.browser_request.command,
        now,
    ) {
        Ok(response) => response,
        Err(error) => {
            crate::target_approve_state_identity_phase::finish_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::target_approve_state_identity_phase::finish_unknown(state, &operation, now)?;
    crate::source_approve_verify::finish(
        &config.0,
        &value.approval.browser_request,
        &value.selected_begin,
        &response,
        now,
    )?;
    crate::target_approve_state_transition::finish_received(state, &operation, &response, now)
}

pub(super) fn prepare_current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: TargetApproveResume,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let request = identity.prepare_current_identity(&config.0, now)?;
    crate::target_approve_state_transition::current_prepared(state, &operation, &request, now)
}

pub(super) fn current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: TargetApproveResume,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::target_approve_state_identity_phase::current_invoking(state, &operation, now)?;
    let request = invoking
        .approval
        .current_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let response = match identity.invoke_current_identity(&config.0, request, now) {
        Ok(response) => response,
        Err(error) => {
            crate::target_approve_state_identity_phase::current_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::target_approve_state_identity_phase::current_unknown(state, &operation, now)?;
    crate::target_approve_current::verify(config, state, &response, now)?;
    crate::target_approve_state_transition::current_received(state, &operation, &response, now, now)
}

pub(super) fn observe(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    value: TargetApproveResume,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::target_approve_state_identity_phase::observe_invoking(state, &operation, now)?;
    if let Err(error) = crate::target_approve_current::observe(config, state, &invoking) {
        crate::target_approve_state_identity_phase::observe_unknown(state, &operation, now)?;
        return Err(error);
    }
    let unknown =
        crate::target_approve_state_identity_phase::observe_unknown(state, &operation, now)?;
    let request = crate::target_approve_verify::pa_request(&config.0, &unknown, now)?;
    crate::target_approve_state_transition::current_complete(state, &operation, &request, now)
}
