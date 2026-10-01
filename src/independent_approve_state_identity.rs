use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    config::AgentConfigDocument,
    independent_approve_state_types::{
        IndependentApprovePhaseV1 as Phase, IndependentApproveResume,
    },
    replay::DurableSecurityState,
};

pub(crate) fn finish_received(
    state: &DurableSecurityState,
    operation: &str,
    finish: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != Phase::FinishUnknown || finish.request != record.finish_request {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.finish_exchange = Some(finish.clone());
        record.phase = Phase::CurrentRequestPrepared;
        Ok(())
    })
}

pub(crate) fn current_prepared(
    state: &DurableSecurityState,
    operation: &str,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != Phase::CurrentRequestPrepared {
            return Err(AgentError::OperationReplay);
        }
        record.current_request = Some(request.clone());
        record.phase = Phase::CurrentPrepared;
        Ok(())
    })
}

pub(crate) fn current_received(
    state: &DurableSecurityState,
    operation: &str,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != Phase::CurrentUnknown
            || record.current_request.as_ref() != Some(&current.request)
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_exchange = Some(current.clone());
        record.phase = Phase::CurrentObservePrepared;
        Ok(())
    })
}

pub(crate) fn observation_complete(
    config: &AgentConfigDocument,
    state: &DurableSecurityState,
    operation: &str,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let wire = serde_json::to_string(request).map_err(|_| AgentError::RequestInvalid)?;
    crate::independent_approve_state_update::apply(state, operation, now, |record| {
        if record.phase != Phase::CurrentObserveUnknown {
            return Err(AgentError::OperationReplay);
        }
        record.current_observed_at_epoch_s = Some(now);
        record.approval_request_json = Some(wire.clone());
        record.approval_request = Some(request.clone());
        record.approval_key_id = Some(config.recovery_approval_key_id.clone());
        record.approval_key_fingerprint = Some(config.recovery_approval_key_fingerprint.clone());
        record.approval_public_key_hex = Some(config.recovery_approval_public_key_hex.clone());
        record.phase = Phase::ApprovalPrepared;
        Ok(())
    })
}
