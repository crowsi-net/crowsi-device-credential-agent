use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupPhaseV1, verify_authority_exchange_historic,
};

use crate::{AgentError, actor_options_state_types::ActorPreparedLookupV1};

pub(super) fn valid(value: &ActorPreparedLookupV1) -> Result<(), AgentError> {
    match value.request.phase {
        EndpointPreparedLookupPhaseV1::Approval => approval(value),
        EndpointPreparedLookupPhaseV1::Target
        | EndpointPreparedLookupPhaseV1::Cancel
        | EndpointPreparedLookupPhaseV1::Reconcile => (value.revocation_response_trust.is_none()
            && value.response.revocation_begin_exchange.is_none())
        .then_some(())
        .ok_or(AgentError::AuthorityRollback),
    }
}

fn approval(value: &ActorPreparedLookupV1) -> Result<(), AgentError> {
    let trust = value
        .revocation_response_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let begun = value
        .response
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let exact = trust.key_id == begun.response.key_id
        && trust.minimum_config_generation == begun.response.config_generation;
    if !exact {
        return Err(AgentError::AuthorityRollback);
    }
    verify_authority_exchange_historic(
        begun,
        begun.request.command.type_name(),
        trust.minimum_config_generation,
        &trust.key_id,
        &trust.public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)
}
