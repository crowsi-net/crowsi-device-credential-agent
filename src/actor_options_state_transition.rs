use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    actor_options_state_types::{ActorOptionsPhaseV1, ActorOptionsResume},
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn begin_complete(
    state: &DurableSecurityState,
    operation: &str,
    begin: &SignedAuthorityExchangeV1,
    envelope: &EndpointManagementEnvelopeV2,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    let wire = serde_json::to_string(envelope).map_err(|_| AgentError::RequestInvalid)?;
    if wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::RequestInvalid);
    }
    state.transaction_namespaces(|values| {
        let (prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        let attempt = fresh
            .actor_records
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let record = journal
            .actor_options
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != ActorOptionsPhaseV1::BeginPrepared {
            let same = matches!(
                record.phase,
                ActorOptionsPhaseV1::CentralPrepared
                    | ActorOptionsPhaseV1::CentralInvoking
                    | ActorOptionsPhaseV1::Unknown
            ) && attempt.exchange.as_ref() == Some(begin)
                && record.central_envelope.as_ref() == Some(envelope)
                && record.central_envelope_json.as_deref() == Some(&wire);
            if same {
                let result =
                    crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
                return Ok((result, false));
            }
            return Err(AgentError::OperationReplay);
        }
        if attempt.request != begin.request {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        attempt.exchange = Some(begin.clone());
        record.central_envelope = Some(envelope.clone());
        record.central_envelope_json = Some(wire);
        record.phase = ActorOptionsPhaseV1::CentralPrepared;
        record.expires_at_epoch_s = crate::actor_options_state::expiration(
            record,
            prepared.actor_records.get(operation),
            fresh.actor_records.get(operation),
        )?;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
