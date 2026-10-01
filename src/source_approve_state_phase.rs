use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

macro_rules! transition {
    ($name:ident, $phase:ident) => {
        pub(crate) fn $name(
            state: &DurableSecurityState,
            operation: &str,
            now: u64,
        ) -> Result<SourceApproveResume, AgentError> {
            phase(state, operation, SourceApprovePhaseV1::$phase, now)
        }
    };
}

transition!(current_invoking, CurrentInvoking);
transition!(current_unknown, CurrentUnknown);
transition!(observe_invoking, CurrentObserveInvoking);
transition!(observe_unknown, CurrentObserveUnknown);
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
transition!(invoking, CentralInvoking);
transition!(unknown, Unknown);

fn phase(
    state: &DurableSecurityState,
    operation: &str,
    next: SourceApprovePhaseV1,
    now: u64,
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
        let allowed = matches!(
            (record.phase, next),
            (
                SourceApprovePhaseV1::CurrentPrepared,
                SourceApprovePhaseV1::CurrentInvoking
            ) | (
                SourceApprovePhaseV1::CurrentInvoking,
                SourceApprovePhaseV1::CurrentUnknown
            ) | (
                SourceApprovePhaseV1::CurrentUnknown,
                SourceApprovePhaseV1::CurrentInvoking
            ) | (
                SourceApprovePhaseV1::CurrentObservePrepared,
                SourceApprovePhaseV1::CurrentObserveInvoking
            ) | (
                SourceApprovePhaseV1::CurrentObserveInvoking,
                SourceApprovePhaseV1::CurrentObserveUnknown
            ) | (
                SourceApprovePhaseV1::CurrentObserveUnknown,
                SourceApprovePhaseV1::CurrentObserveInvoking
            ) | (
                SourceApprovePhaseV1::ReservationCurrentPrepared,
                SourceApprovePhaseV1::ReservationCurrentInvoking
            ) | (
                SourceApprovePhaseV1::ReservationCurrentInvoking,
                SourceApprovePhaseV1::ReservationCurrentUnknown
            ) | (
                SourceApprovePhaseV1::ReservationCurrentUnknown,
                SourceApprovePhaseV1::ReservationCurrentInvoking
            ) | (
                SourceApprovePhaseV1::ReservationCurrentObservePrepared,
                SourceApprovePhaseV1::ReservationCurrentObserveInvoking
            ) | (
                SourceApprovePhaseV1::ReservationCurrentObserveInvoking,
                SourceApprovePhaseV1::ReservationCurrentObserveUnknown
            ) | (
                SourceApprovePhaseV1::ReservationCurrentObserveUnknown,
                SourceApprovePhaseV1::ReservationCurrentObserveInvoking
            ) | (
                SourceApprovePhaseV1::ExecutionReservePrepared,
                SourceApprovePhaseV1::ExecutionReserveInvoking
            ) | (
                SourceApprovePhaseV1::ExecutionReserveInvoking,
                SourceApprovePhaseV1::ExecutionReserveUnknown
            ) | (
                SourceApprovePhaseV1::ExecutionReserveUnknown,
                SourceApprovePhaseV1::ExecutionReserveInvoking
            ) | (
                SourceApprovePhaseV1::CentralPrepared,
                SourceApprovePhaseV1::CentralInvoking
            ) | (
                SourceApprovePhaseV1::CentralInvoking,
                SourceApprovePhaseV1::Unknown
            ) | (
                SourceApprovePhaseV1::Unknown,
                SourceApprovePhaseV1::CentralInvoking
            )
        );
        if !allowed {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
