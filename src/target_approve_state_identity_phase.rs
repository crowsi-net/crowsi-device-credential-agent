use crate::{
    AgentError,
    replay::DurableSecurityState,
    target_approve_state_types::{TargetApprovePhaseV1, TargetApproveResume},
};

macro_rules! transition {
    ($name:ident, $phase:ident) => {
        pub(crate) fn $name(
            state: &DurableSecurityState,
            operation: &str,
            now: u64,
        ) -> Result<TargetApproveResume, AgentError> {
            crate::target_approve_state_phase::change(
                state,
                operation,
                TargetApprovePhaseV1::$phase,
                now,
            )
        }
    };
}

transition!(finish_invoking, FinishInvoking);
transition!(finish_unknown, FinishUnknown);
transition!(current_invoking, CurrentInvoking);
transition!(current_unknown, CurrentUnknown);
transition!(observe_invoking, CurrentObserveInvoking);
transition!(observe_unknown, CurrentObserveUnknown);
