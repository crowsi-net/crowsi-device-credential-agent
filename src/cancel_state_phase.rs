use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1, CancelRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

macro_rules! transition {
    ($name:ident, $phase:ident) => {
        pub(crate) fn $name(
            state: &DurableSecurityState,
            operation: &str,
            now: u64,
        ) -> Result<Box<CancelRecordV1>, AgentError> {
            phase(state, operation, CancelPhaseV1::$phase, now)
        }
    };
}

transition!(current_invoking, CurrentInvoking);
transition!(current_unknown, CurrentUnknown);
transition!(observe_invoking, CurrentObserveInvoking);
transition!(observe_unknown, CurrentObserveUnknown);
transition!(invoking, CentralInvoking);
transition!(unknown, Unknown);
transition!(execution_cancel_invoking, ExecutionCancelInvoking);
transition!(execution_cancel_unknown, ExecutionCancelUnknown);
transition!(cancel_pending_invoking, CancelPendingInvoking);
transition!(cancel_pending_unknown, CancelPendingUnknown);
transition!(cancel_finalize_invoking, CancelFinalizeInvoking);
transition!(cancel_finalize_unknown, CancelFinalizeUnknown);
transition!(cleanup_ack_invoking, CleanupAckInvoking);
transition!(cleanup_ack_unknown, CleanupAckUnknown);
transition!(cleanup_complete_invoking, CleanupCompleteInvoking);
transition!(cleanup_complete_unknown, CleanupCompleteUnknown);
transition!(
    cleanup_complete_cleanup_prepared,
    CleanupCompleteCleanupPrepared
);
transition!(
    cleanup_complete_cleanup_invoking,
    CleanupCompleteCleanupInvoking
);
transition!(
    cleanup_complete_cleanup_unknown,
    CleanupCompleteCleanupUnknown
);
transition!(cleanup_complete_ack_invoking, CleanupCompleteAckInvoking);
transition!(cleanup_complete_ack_unknown, CleanupCompleteAckUnknown);

fn phase(
    state: &DurableSecurityState,
    operation: &str,
    next: CancelPhaseV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if !crate::cancel_state_phase_allowed::valid(record.phase, next) {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
