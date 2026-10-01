use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_options_state::{self, SourceOptionsPhaseV1, SourceOptionsResume},
};

pub(crate) fn begin_complete(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    envelope: &EndpointManagementEnvelopeV2,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    let wire = serde_json::to_string(envelope).map_err(|_| AgentError::RequestInvalid)?;
    if wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::RequestInvalid);
    }
    let digest = source_options_state::digest("CROWSI-ENDPOINT-CENTRAL-ENVELOPE-V2", envelope)?;
    state.transaction_namespaces(|values| {
        let (prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        let attempt = fresh
            .records
            .get(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if attempt.request != exchange.request {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        if attempt
            .exchange
            .as_ref()
            .is_some_and(|value| value != exchange)
        {
            return Err(AgentError::AuthorityRollback);
        }
        fresh
            .records
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?
            .exchange = Some(exchange.clone());
        let expires_at_epoch_s = crate::source_options_state_validation::expiration(
            prepared
                .records
                .get(operation)
                .ok_or(AgentError::AuthorityRollback)?,
            fresh
                .records
                .get(operation)
                .ok_or(AgentError::AuthorityRollback)?,
        )?;
        let record = journal
            .records
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != SourceOptionsPhaseV1::BeginPrepared {
            let same = fresh
                .records
                .get(operation)
                .and_then(|value| value.exchange.as_ref())
                == Some(exchange)
                && record.central_envelope_json.as_deref() == Some(&wire)
                && record.central_envelope_digest_sha256.as_deref() == Some(&digest);
            if same {
                let result = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
                return Ok((result, false));
            }
            return Err(AgentError::OperationReplay);
        }
        record.phase = SourceOptionsPhaseV1::CentralPrepared;
        record.central_envelope_json = Some(wire);
        record.central_envelope_digest_sha256 = Some(digest);
        record.expires_at_epoch_s = expires_at_epoch_s;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn invoking(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    phase(state, operation, SourceOptionsPhaseV1::CentralInvoking, now)
}

pub(crate) fn unknown(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    phase(state, operation, SourceOptionsPhaseV1::Unknown, now)
}

fn phase(
    state: &DurableSecurityState,
    operation: &str,
    next: SourceOptionsPhaseV1,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .records
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let allowed = matches!(
            (record.phase, next),
            (
                SourceOptionsPhaseV1::CentralPrepared,
                SourceOptionsPhaseV1::CentralInvoking
            ) | (
                SourceOptionsPhaseV1::CentralInvoking,
                SourceOptionsPhaseV1::Unknown
            ) | (
                SourceOptionsPhaseV1::Unknown,
                SourceOptionsPhaseV1::CentralInvoking
            )
        );
        if !allowed {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        let result = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
