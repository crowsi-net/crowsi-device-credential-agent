use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionReserveRequestV1, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1 as P, SourceApproveResume},
    source_options_state,
};

pub(super) fn received(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    update(state, operation, now, |record| {
        if record.phase != P::ReservationCurrentUnknown
            || record.reservation_current_request.as_ref() != Some(&exchange.request)
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.reservation_current_exchange = Some(exchange.clone());
        record.phase = P::ReservationCurrentObservePrepared;
        Ok(())
    })
}

pub(super) fn observation_complete(
    state: &DurableSecurityState,
    operation: &str,
    request: &EndpointRevocationExecutionReserveRequestV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let wire = serde_json::to_string(request).map_err(|_| AgentError::RequestInvalid)?;
    if wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::RequestInvalid);
    }
    update(state, operation, now, |record| {
        if record.phase != P::ReservationCurrentObserveUnknown {
            return Err(AgentError::OperationReplay);
        }
        record.reservation_current_observed_at_epoch_s = Some(now);
        record.execution_reserve_request_json = Some(wire.clone());
        record.execution_reserve_request = Some(request.clone());
        record.phase = P::ExecutionReservePrepared;
        Ok(())
    })
}

fn update(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
    change: impl FnOnce(
        &mut crate::source_approve_state_types::SourceApproveRecordV1,
    ) -> Result<(), AgentError>,
) -> Result<SourceApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let selected = fresh
            .records
            .get(operation)
            .and_then(|value| value.exchange.as_ref())
            .ok_or(AgentError::AuthorityRollback)?;
        let record = journal
            .source_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if now < record.updated_at_epoch_s {
            return Err(AgentError::AuthorityRollback);
        }
        change(record)?;
        record.updated_at_epoch_s = now;
        record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
