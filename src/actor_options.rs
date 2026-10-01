use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, actor_options_state_types::ActorOptionsPhaseV1,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(crate) fn handle<T: AuthorityTransport, I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let mut value =
        crate::actor_options_prepare::load_or_reserve(config, state, identity, browser, now)?;
    loop {
        value = crate::actor_options_prepare::unexpired(value, now)?;
        let operation = value.journal.operation_id.clone();
        match value.journal.phase {
            ActorOptionsPhaseV1::CurrentInvoking => {
                value = crate::actor_options_state_phase::current_unknown(state, &operation, now)?;
            }
            ActorOptionsPhaseV1::CurrentPrepared | ActorOptionsPhaseV1::CurrentUnknown => {
                value = crate::actor_options_identity_flow::current(
                    config, state, identity, value, now,
                )?;
            }
            ActorOptionsPhaseV1::CurrentObserveInvoking => {
                value = crate::actor_options_state_phase::observe_unknown(state, &operation, now)?;
            }
            ActorOptionsPhaseV1::CurrentObservePrepared
            | ActorOptionsPhaseV1::CurrentObserveUnknown => {
                value = crate::actor_options_identity_flow::observe(
                    config, state, browser, value, now,
                )?;
            }
            ActorOptionsPhaseV1::LookupPrepared => {
                let request = value
                    .journal
                    .lookup_request
                    .as_ref()
                    .ok_or(AgentError::AuthorityRollback)?;
                let lookup = crate::prepared_lookup::invoke(&config.0, transport, request, now)?;
                let begin = identity.prepare_begin_fresh_uv(
                    &config.0,
                    value
                        .journal
                        .current_exchange
                        .as_ref()
                        .ok_or(AgentError::AuthorityRollback)?,
                    &lookup.value.prepared,
                    now,
                )?;
                value = crate::actor_options_state_identity::lookup_complete(
                    state, &operation, &lookup, &begin, now,
                )?;
            }
            ActorOptionsPhaseV1::BeginPrepared => {
                let fresh = value.fresh.as_ref().ok_or(AgentError::AuthorityRollback)?;
                let begin = identity.invoke_begin_fresh_uv(&config.0, &fresh.request, now)?;
                let prepared = value
                    .prepared
                    .as_ref()
                    .ok_or(AgentError::AuthorityRollback)?;
                let current = value
                    .journal
                    .current_exchange
                    .as_ref()
                    .ok_or(AgentError::AuthorityRollback)?;
                let envelope = crate::actor_options_verify::envelope(
                    &config.0,
                    browser,
                    &prepared.response,
                    current,
                    &begin,
                    now,
                )?;
                value = crate::actor_options_state_transition::begin_complete(
                    state, &operation, &begin, &envelope, now,
                )?;
            }
            ActorOptionsPhaseV1::CentralInvoking => {
                value = crate::actor_options_state_phase::unknown(state, &operation, now)?;
            }
            ActorOptionsPhaseV1::CentralPrepared | ActorOptionsPhaseV1::Unknown => {
                return crate::actor_options_response::invoke(
                    config, state, transport, browser, value, now,
                );
            }
            ActorOptionsPhaseV1::Complete => {
                return crate::actor_options_response::completed(
                    config, state, transport, browser, &value, now,
                );
            }
        }
    }
}
