use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationFinalizeRequestV1, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    independent_approve_state_types::{IndependentApprovePhaseV1 as P, IndependentApproveResume},
    replay::DurableSecurityState,
};

pub(crate) fn approval_received(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != P::ApprovalUnknown
            || record.approval_request.as_ref() != Some(&exchange.request)
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.approval_exchange = Some(exchange.clone());
        record.phase = P::ApprovalAccepted;
        Ok(())
    })
}

pub(crate) fn final_received(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != P::FinalUnknown
            || record.final_request.as_ref() != Some(&exchange.request)
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.final_exchange = Some(exchange.clone());
        record.phase = P::FinalAccepted;
        Ok(())
    })
}

pub(crate) fn finalize_prepared(
    state: &DurableSecurityState,
    operation: &str,
    request: &EndpointIndependentRevocationFinalizeRequestV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let wire = serde_json::to_string(request).map_err(|_| AgentError::RequestInvalid)?;
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != P::FinalAccepted {
            return Err(AgentError::OperationReplay);
        }
        record.finalize_request_json = Some(wire.clone());
        record.finalize_request = Some(request.clone());
        record.phase = P::FinalizePrepared;
        Ok(())
    })
}
