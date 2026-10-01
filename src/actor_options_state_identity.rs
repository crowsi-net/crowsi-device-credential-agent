use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupRequestV1, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    actor_options_state_types::{ActorOptionsPhaseV1, ActorOptionsResume, ActorPreparedLookupV1},
    prepared_lookup::VerifiedPreparedLookup,
    replay::DurableSecurityState,
    source_options_state,
    source_options_state_types::FreshUvAttemptV1,
};

pub(crate) fn current_received(
    state: &DurableSecurityState,
    operation: &str,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .actor_options
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != ActorOptionsPhaseV1::CurrentUnknown
            || current.request != record.current_request
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_exchange = Some(current.clone());
        record.phase = ActorOptionsPhaseV1::CurrentObservePrepared;
        record.expires_at_epoch_s = crate::actor_options_state::expiration(record, None, None)?;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn observation_complete(
    state: &DurableSecurityState,
    operation: &str,
    lookup: &EndpointPreparedLookupRequestV1,
    observed_at: u64,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .actor_options
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let current = record
            .current_exchange
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != ActorOptionsPhaseV1::CurrentObserveUnknown
            || lookup.identity_exchange != *current
        {
            return Err(AgentError::OperationReplay);
        }
        record.current_observed_at_epoch_s = Some(observed_at);
        record.lookup_request = Some(lookup.clone());
        record.phase = ActorOptionsPhaseV1::LookupPrepared;
        record.expires_at_epoch_s = crate::actor_options_state::expiration(record, None, None)?;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn lookup_complete(
    state: &DurableSecurityState,
    operation: &str,
    lookup: &VerifiedPreparedLookup,
    begin: &AuthorityRequestV1,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (mut prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .actor_options
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != ActorOptionsPhaseV1::LookupPrepared {
            let winner = record.phase == ActorOptionsPhaseV1::BeginPrepared
                && prepared
                    .actor_records
                    .get(operation)
                    .is_some_and(|value| value.response == lookup.value)
                && fresh.actor_records.contains_key(operation);
            if winner {
                let result =
                    crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
                return Ok((result, false));
            }
            return Err(AgentError::OperationReplay);
        }
        let request = record
            .lookup_request
            .clone()
            .ok_or(AgentError::AuthorityRollback)?;
        if lookup.value.prepared.operation_id != operation {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        prepared.actor_records.insert(
            operation.into(),
            ActorPreparedLookupV1 {
                operation_id: operation.into(),
                request,
                response_json: lookup.wire.clone(),
                response: lookup.value.clone(),
                revocation_response_trust: lookup.revocation_response_trust.clone(),
            },
        );
        fresh.actor_records.insert(
            operation.into(),
            FreshUvAttemptV1 {
                operation_id: operation.into(),
                request: begin.clone(),
                exchange: None,
            },
        );
        record.phase = ActorOptionsPhaseV1::BeginPrepared;
        record.expires_at_epoch_s = crate::actor_options_state::expiration(
            record,
            prepared.actor_records.get(operation),
            fresh.actor_records.get(operation),
        )?;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
