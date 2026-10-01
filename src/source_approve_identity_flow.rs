use crowsi_credential_authority_contracts::{ManagementIntentV2, ManagementRequestV2};

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_approve_state_types::SourceApproveResume,
};

pub(crate) fn current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: SourceApproveResume,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let operation = &value.source.prepared.operation_id;
    let request = value
        .approval
        .current_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    crate::source_approve_state_phase::current_invoking(state, operation, now)?;
    let response = match identity.invoke_current_identity(&config.0, request, now) {
        Ok(response) => response,
        Err(error) => {
            crate::source_approve_state_phase::current_unknown(state, operation, now)?;
            return Err(error);
        }
    };
    crate::source_approve_state_phase::current_unknown(state, operation, now)?;
    crate::core_identity::verify(config, state, &response, now)?;
    crate::source_approve_state_current::received(state, operation, &response, now)
}

pub(crate) fn observe<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    value: SourceApproveResume,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let operation = &value.source.prepared.operation_id;
    let current = value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    crate::source_approve_state_phase::observe_invoking(state, operation, now)?;
    if let Err(error) = crate::core_identity::verify_and_observe(config, state, current, now) {
        crate::source_approve_state_phase::observe_unknown(state, operation, now)?;
        return Err(error);
    }
    crate::source_approve_state_phase::observe_unknown(state, operation, now)?;
    if matches!(
        value.source.prepared.intent,
        ManagementIntentV2::DeviceTransfer { .. }
    ) {
        transfer(config, state, browser, &value, current, now)
    } else {
        crate::source_approve_revocation_flow::after_current(
            config, state, identity, browser, &value, current, now,
        )
    }
}

fn transfer(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &SourceApproveResume,
    current: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let envelope = crate::source_approve_verify::envelope(
        &config.0,
        browser,
        &value.source.prepared,
        crate::source_approve_verify::Evidence {
            selected_identity: &value.source.selected_identity_exchange,
            selected_begin: &value.selected_begin,
            finish,
            current_identity: current,
            revocation: None,
        },
        now,
    )?;
    crate::source_approve_state_transition::current_complete(
        state,
        &value.source.prepared.operation_id,
        current,
        &envelope,
        now,
    )
}
