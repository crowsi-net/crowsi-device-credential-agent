use crate::{
    AgentError,
    independent_approve_state_types::{IndependentApprovePhaseV1, IndependentApproveResume},
    replay::DurableSecurityState,
};

macro_rules! transition {
    ($name:ident, $phase:ident) => {
        pub(crate) fn $name(
            state: &DurableSecurityState,
            operation: &str,
            now: u64,
        ) -> Result<IndependentApproveResume, AgentError> {
            change(state, operation, IndependentApprovePhaseV1::$phase, now)
        }
    };
}

transition!(finish_invoking, FinishInvoking);
transition!(finish_unknown, FinishUnknown);
transition!(current_invoking, CurrentInvoking);
transition!(current_unknown, CurrentUnknown);
transition!(observe_invoking, CurrentObserveInvoking);
transition!(observe_unknown, CurrentObserveUnknown);
transition!(approval_invoking, ApprovalInvoking);
transition!(approval_unknown, ApprovalUnknown);
transition!(pre_final_invoking, PreFinalInvoking);
transition!(pre_final_unknown, PreFinalUnknown);
transition!(reservation_current_invoking, ReservationCurrentInvoking);
transition!(reservation_current_unknown, ReservationCurrentUnknown);
transition!(
    reservation_observe_invoking,
    ReservationCurrentObserveInvoking
);
transition!(
    reservation_observe_unknown,
    ReservationCurrentObserveUnknown
);
transition!(execution_reserve_invoking, ExecutionReserveInvoking);
transition!(execution_reserve_unknown, ExecutionReserveUnknown);
transition!(final_invoking, FinalInvoking);
transition!(final_unknown, FinalUnknown);
transition!(finalize_invoking, FinalizeInvoking);
transition!(finalize_unknown, FinalizeUnknown);

fn change(
    state: &DurableSecurityState,
    operation: &str,
    next: IndependentApprovePhaseV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = crate::source_options_state::documents(values)?;
        let record = journal
            .independent_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if now < record.updated_at_epoch_s {
            return Err(AgentError::AuthorityRollback);
        }
        if !crate::independent_approve_state_phase_allowed::allowed(record.phase, next) {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        let shell =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        let expires = crate::independent_approve_state_expiration::expiration(&shell)?;
        journal
            .independent_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?
            .expires_at_epoch_s = expires;
        crate::source_options_state::validate(&prepared, &fresh, &journal)?;
        let result =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
