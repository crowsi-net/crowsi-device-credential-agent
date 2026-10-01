use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionReserveRequestV1, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    independent_approve_state_types::{IndependentApprovePhaseV1 as P, IndependentApproveResume},
    replay::DurableSecurityState,
};

pub(super) fn prepared(
    state: &DurableSecurityState,
    operation: &str,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != P::PreFinalAccepted {
            return Err(AgentError::OperationReplay);
        }
        record.reservation_current_request = Some(request.clone());
        record.phase = P::ReservationCurrentPrepared;
        Ok(())
    })
}

pub(super) fn received(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        let exact = record.phase == P::ReservationCurrentUnknown
            && record.reservation_current_request.as_ref() == Some(&exchange.request);
        if !exact {
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
) -> Result<IndependentApproveResume, AgentError> {
    let wire = serde_json::to_string(request).map_err(|_| AgentError::RequestInvalid)?;
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
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
