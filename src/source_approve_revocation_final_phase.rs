use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn invoking(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    phase(
        state,
        operation,
        SourceApprovePhaseV1::RevocationFinalInvoking,
        now,
    )
}

pub(crate) fn unknown(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    phase(
        state,
        operation,
        SourceApprovePhaseV1::RevocationFinalUnknown,
        now,
    )
}

fn phase(
    state: &DurableSecurityState,
    operation: &str,
    next: SourceApprovePhaseV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .source_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let allowed = matches!(
            (record.phase, next),
            (
                SourceApprovePhaseV1::RevocationFinalPrepared,
                SourceApprovePhaseV1::RevocationFinalInvoking
            ) | (
                SourceApprovePhaseV1::RevocationFinalInvoking,
                SourceApprovePhaseV1::RevocationFinalUnknown
            ) | (
                SourceApprovePhaseV1::RevocationFinalUnknown,
                SourceApprovePhaseV1::RevocationFinalInvoking
            )
        );
        if !allowed {
            return Err(AgentError::OperationReplay);
        }
        record.phase = next;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
