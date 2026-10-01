use crate::{
    AgentError,
    actor_options_state_types::{ActorOptionsPhaseV1, ActorOptionsResume},
    replay::DurableSecurityState,
    source_options_state,
};

macro_rules! transition {
    ($name:ident, $phase:ident) => {
        pub(crate) fn $name(
            state: &DurableSecurityState,
            operation: &str,
            now: u64,
        ) -> Result<ActorOptionsResume, AgentError> {
            phase(state, operation, ActorOptionsPhaseV1::$phase, now)
        }
    };
}

transition!(current_invoking, CurrentInvoking);
transition!(current_unknown, CurrentUnknown);
transition!(observe_invoking, CurrentObserveInvoking);
transition!(observe_unknown, CurrentObserveUnknown);
transition!(invoking, CentralInvoking);
transition!(unknown, Unknown);

fn phase(
    state: &DurableSecurityState,
    operation: &str,
    next: ActorOptionsPhaseV1,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .actor_options
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let allowed = matches!(
            (record.phase, next),
            (
                ActorOptionsPhaseV1::CurrentPrepared,
                ActorOptionsPhaseV1::CurrentInvoking
            ) | (
                ActorOptionsPhaseV1::CurrentInvoking,
                ActorOptionsPhaseV1::CurrentUnknown
            ) | (
                ActorOptionsPhaseV1::CurrentUnknown,
                ActorOptionsPhaseV1::CurrentInvoking
            ) | (
                ActorOptionsPhaseV1::CurrentObservePrepared,
                ActorOptionsPhaseV1::CurrentObserveInvoking
            ) | (
                ActorOptionsPhaseV1::CurrentObserveInvoking,
                ActorOptionsPhaseV1::CurrentObserveUnknown
            ) | (
                ActorOptionsPhaseV1::CurrentObserveUnknown,
                ActorOptionsPhaseV1::CurrentObserveInvoking
            ) | (
                ActorOptionsPhaseV1::CentralPrepared,
                ActorOptionsPhaseV1::CentralInvoking
            ) | (
                ActorOptionsPhaseV1::CentralInvoking,
                ActorOptionsPhaseV1::Unknown
            ) | (
                ActorOptionsPhaseV1::Unknown,
                ActorOptionsPhaseV1::CentralInvoking
            )
        );
        if !allowed {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::actor_options_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
