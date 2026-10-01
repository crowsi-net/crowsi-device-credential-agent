use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, actor_options_state_types::ActorOptionsResume,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
};

pub(crate) fn current<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: ActorOptionsResume,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    let operation = &value.journal.operation_id;
    crate::actor_options_state_phase::current_invoking(state, operation, now)?;
    let response =
        match identity.invoke_current_identity(&config.0, &value.journal.current_request, now) {
            Ok(response) => response,
            Err(error) => {
                crate::actor_options_state_phase::current_unknown(state, operation, now)?;
                return Err(error);
            }
        };
    crate::actor_options_state_phase::current_unknown(state, operation, now)?;
    crate::core_identity::verify(config, state, &response, now)?;
    crate::actor_options_state_identity::current_received(state, operation, &response, now)
}

pub(crate) fn observe(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: ActorOptionsResume,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    let operation = &value.journal.operation_id;
    crate::actor_options_state_phase::observe_invoking(state, operation, now)?;
    let current = value
        .journal
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if let Err(error) = crate::core_identity::verify_and_observe(config, state, current, now) {
        crate::actor_options_state_phase::observe_unknown(state, operation, now)?;
        return Err(error);
    }
    crate::actor_options_state_phase::observe_unknown(state, operation, now)?;
    let lookup = crate::prepared_lookup::build(
        browser,
        crate::actor_options_prepare::phase(browser)?,
        current,
    )?;
    crate::actor_options_state_identity::observation_complete(state, operation, &lookup, now, now)
}
