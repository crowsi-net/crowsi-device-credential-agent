use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_options_state,
    target_approve_state_types::{TargetApprovePhaseV1, TargetApproveResume},
};

pub(crate) fn pa_invoking(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    change(state, operation, TargetApprovePhaseV1::PaInvoking, now)
}

pub(crate) fn pa_unknown(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    change(state, operation, TargetApprovePhaseV1::PaUnknown, now)
}

pub(crate) fn custody_invoking(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    change(state, operation, TargetApprovePhaseV1::CustodyInvoking, now)
}

pub(crate) fn custody_unknown(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    change(state, operation, TargetApprovePhaseV1::CustodyUnknown, now)
}

pub(crate) fn central_invoking(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    change(state, operation, TargetApprovePhaseV1::CentralInvoking, now)
}

pub(crate) fn central_unknown(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    change(state, operation, TargetApprovePhaseV1::Unknown, now)
}

pub(super) fn change(
    state: &DurableSecurityState,
    operation: &str,
    next: TargetApprovePhaseV1,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .target_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if now < record.updated_at_epoch_s {
            return Err(AgentError::AuthorityRollback);
        }
        if now >= record.expires_at_epoch_s
            && !crate::target_approve_state::can_resume_expired(record)
        {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        if !allowed(record.phase, next) {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

const fn allowed(current: TargetApprovePhaseV1, next: TargetApprovePhaseV1) -> bool {
    matches!(
        (current, next),
        (
            TargetApprovePhaseV1::FinishPrepared,
            TargetApprovePhaseV1::FinishInvoking
        ) | (
            TargetApprovePhaseV1::FinishUnknown,
            TargetApprovePhaseV1::FinishInvoking
        ) | (
            TargetApprovePhaseV1::FinishInvoking,
            TargetApprovePhaseV1::FinishUnknown
        ) | (
            TargetApprovePhaseV1::CurrentPrepared,
            TargetApprovePhaseV1::CurrentInvoking
        ) | (
            TargetApprovePhaseV1::CurrentUnknown,
            TargetApprovePhaseV1::CurrentInvoking
        ) | (
            TargetApprovePhaseV1::CurrentInvoking,
            TargetApprovePhaseV1::CurrentUnknown
        ) | (
            TargetApprovePhaseV1::CurrentObservePrepared,
            TargetApprovePhaseV1::CurrentObserveInvoking
        ) | (
            TargetApprovePhaseV1::CurrentObserveUnknown,
            TargetApprovePhaseV1::CurrentObserveInvoking
        ) | (
            TargetApprovePhaseV1::CurrentObserveInvoking,
            TargetApprovePhaseV1::CurrentObserveUnknown
        ) | (
            TargetApprovePhaseV1::PaPrepared,
            TargetApprovePhaseV1::PaInvoking
        ) | (
            TargetApprovePhaseV1::PaUnknown,
            TargetApprovePhaseV1::PaInvoking
        ) | (
            TargetApprovePhaseV1::PaInvoking,
            TargetApprovePhaseV1::PaUnknown
        ) | (
            TargetApprovePhaseV1::CustodyPrepared,
            TargetApprovePhaseV1::CustodyInvoking
        ) | (
            TargetApprovePhaseV1::CustodyUnknown,
            TargetApprovePhaseV1::CustodyInvoking
        ) | (
            TargetApprovePhaseV1::CustodyInvoking,
            TargetApprovePhaseV1::CustodyUnknown
        ) | (
            TargetApprovePhaseV1::CentralPrepared,
            TargetApprovePhaseV1::CentralInvoking
        ) | (
            TargetApprovePhaseV1::Unknown,
            TargetApprovePhaseV1::CentralInvoking
        ) | (
            TargetApprovePhaseV1::CentralInvoking,
            TargetApprovePhaseV1::Unknown
        )
    )
}
