use crate::{
    AgentError,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

macro_rules! transition {
    ($name:ident, $phase:ident) => {
        pub(crate) fn $name(
            state: &DurableSecurityState,
            key: &str,
            now: u64,
        ) -> Result<ReconcileRecordV1, AgentError> {
            change(state, key, ReconcilePhaseV1::$phase, now)
        }
    };
}

transition!(current_invoking, CurrentInvoking);
transition!(current_unknown, CurrentUnknown);
transition!(observe_invoking, CurrentObserveInvoking);
transition!(observe_unknown, CurrentObserveUnknown);
transition!(lookup_invoking, LookupInvoking);
transition!(lookup_unknown, LookupUnknown);
transition!(central_invoking, CentralInvoking);
transition!(central_unknown, Unknown);

fn change(
    state: &DurableSecurityState,
    key: &str,
    next: ReconcilePhaseV1,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .reconciliations
            .get_mut(key)
            .ok_or(AgentError::AuthorityRollback)?;
        let allowed = matches!(
            (record.phase, next),
            (
                ReconcilePhaseV1::CurrentPrepared,
                ReconcilePhaseV1::CurrentInvoking
            ) | (
                ReconcilePhaseV1::CurrentInvoking,
                ReconcilePhaseV1::CurrentUnknown
            ) | (
                ReconcilePhaseV1::CurrentUnknown,
                ReconcilePhaseV1::CurrentInvoking
            ) | (
                ReconcilePhaseV1::CurrentObservePrepared,
                ReconcilePhaseV1::CurrentObserveInvoking
            ) | (
                ReconcilePhaseV1::CurrentObserveInvoking,
                ReconcilePhaseV1::CurrentObserveUnknown
            ) | (
                ReconcilePhaseV1::CurrentObserveUnknown,
                ReconcilePhaseV1::CurrentObserveInvoking
            ) | (
                ReconcilePhaseV1::LookupPrepared,
                ReconcilePhaseV1::LookupInvoking
            ) | (
                ReconcilePhaseV1::LookupInvoking,
                ReconcilePhaseV1::LookupUnknown
            ) | (
                ReconcilePhaseV1::LookupUnknown,
                ReconcilePhaseV1::LookupInvoking
            ) | (
                ReconcilePhaseV1::CentralPrepared,
                ReconcilePhaseV1::CentralInvoking
            ) | (ReconcilePhaseV1::CentralInvoking, ReconcilePhaseV1::Unknown)
                | (ReconcilePhaseV1::Unknown, ReconcilePhaseV1::CentralInvoking)
        );
        if !allowed || (now >= record.expires_at_epoch_s && !historic(next)) {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::reconcile_state::resume(key, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn historic(value: ReconcilePhaseV1) -> bool {
    matches!(
        value,
        ReconcilePhaseV1::CentralInvoking | ReconcilePhaseV1::Unknown
    )
}
