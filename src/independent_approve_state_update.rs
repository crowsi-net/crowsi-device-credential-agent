use crate::{
    AgentError,
    independent_approve_state_types::{IndependentApproveRecordV1, IndependentApproveResume},
    replay::DurableSecurityState,
};

pub(super) fn apply(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
    change: impl FnOnce(&mut IndependentApproveRecordV1) -> Result<(), AgentError>,
) -> Result<IndependentApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = crate::source_options_state::documents(values)?;
        {
            let record = journal
                .independent_approvals
                .get_mut(operation)
                .ok_or(AgentError::AuthorityRollback)?;
            if now < record.updated_at_epoch_s {
                return Err(AgentError::AuthorityRollback);
            }
            change(record)?;
            record.updated_at_epoch_s = now;
        }
        let resume =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        let expires = crate::independent_approve_state_expiration::expiration(&resume)?;
        let record = journal
            .independent_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        record.expires_at_epoch_s = expires;
        crate::source_options_state::validate(&prepared, &fresh, &journal)?;
        let result =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
