use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use crowsi_windows_operation_contracts::OperationAuthorizeOnceRequestV2;
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_options_state,
    target_approve_state_types::{TargetApprovePhaseV1, TargetApproveResume},
};

pub(crate) fn finish_received(
    state: &DurableSecurityState,
    operation: &str,
    finish: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    update(state, operation, now, |record| {
        if record.phase != TargetApprovePhaseV1::FinishUnknown {
            let same = record.phase == TargetApprovePhaseV1::CurrentRequestPrepared
                && record.finish_exchange.as_ref() == Some(finish);
            return same.then_some(()).ok_or(AgentError::OperationReplay);
        }
        if finish.request != record.finish_request {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.finish_exchange = Some(finish.clone());
        record.phase = TargetApprovePhaseV1::CurrentRequestPrepared;
        Ok(())
    })
}

pub(crate) fn current_prepared(
    state: &DurableSecurityState,
    operation: &str,
    current: &AuthorityRequestV1,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    update(state, operation, now, |record| {
        if record.phase != TargetApprovePhaseV1::CurrentRequestPrepared {
            return Err(AgentError::OperationReplay);
        }
        record.current_request = Some(current.clone());
        record.phase = TargetApprovePhaseV1::CurrentPrepared;
        Ok(())
    })
}

pub(crate) fn current_complete(
    state: &DurableSecurityState,
    operation: &str,
    pa: &OperationAuthorizeOnceRequestV2,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let wire = serde_json::to_string(pa).map_err(|_| AgentError::RequestInvalid)?;
    if wire.len() > crowsi_windows_operation_contracts::MAX_OPERATION_AUTHORIZE_ONCE_BYTES {
        return Err(AgentError::RequestInvalid);
    }
    update(state, operation, now, |record| {
        if record.phase != TargetApprovePhaseV1::CurrentObserveUnknown {
            let same = record.phase == TargetApprovePhaseV1::PaPrepared
                && record.pa_request.as_ref() == Some(pa)
                && record.pa_request_json.as_deref() == Some(wire.as_str());
            return same.then_some(()).ok_or(AgentError::OperationReplay);
        }
        record.pa_request = Some(pa.clone());
        record.pa_request_json = Some(wire.clone());
        record.phase = TargetApprovePhaseV1::PaPrepared;
        Ok(())
    })
}

pub(crate) fn current_received(
    state: &DurableSecurityState,
    operation: &str,
    current: &SignedAuthorityExchangeV1,
    observed_at: u64,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    update(state, operation, now, |record| {
        if record.phase != TargetApprovePhaseV1::CurrentUnknown
            || record.current_request.as_ref() != Some(&current.request)
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_exchange = Some(current.clone());
        record.current_observed_at_epoch_s = Some(observed_at);
        record.phase = TargetApprovePhaseV1::CurrentObservePrepared;
        Ok(())
    })
}

fn update(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
    change: impl FnOnce(
        &mut crate::target_approve_state_types::TargetApproveRecordV1,
    ) -> Result<(), AgentError>,
) -> Result<TargetApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        {
            let record = journal
                .target_approvals
                .get_mut(operation)
                .ok_or(AgentError::AuthorityRollback)?;
            if now < record.updated_at_epoch_s {
                return Err(AgentError::AuthorityRollback);
            }
            change(record)?;
            record.updated_at_epoch_s = now;
        }
        let value = crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        let expires = crate::target_approve_state_expiration::expiration(&value)?;
        if now >= expires {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        journal
            .target_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?
            .expires_at_epoch_s = expires;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
