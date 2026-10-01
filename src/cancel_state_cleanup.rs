use crate::source_options_state_types::{
    FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1,
};

pub(super) fn operation(
    id: &str,
    prepared: &mut PreparedOperationsV1,
    fresh: &mut FreshUvAttemptsV1,
    journal: &mut OperationJournalV1,
    now: u64,
) -> Result<(), crate::AgentError> {
    crate::retired_request_retire::operation(id, prepared, fresh, journal, now)?;
    prepared.records.remove(id);
    prepared.actor_records.remove(id);
    fresh.records.remove(id);
    fresh.actor_records.remove(id);
    journal.records.remove(id);
    journal.source_approvals.remove(id);
    journal.actor_options.remove(id);
    journal.target_approvals.remove(id);
    journal.independent_approvals.remove(id);
    journal.reconciliations.remove(id);
    journal.request_index.retain(|_, operation| operation != id);
    journal
        .source_approval_index
        .retain(|_, operation| operation != id);
    journal
        .actor_options_index
        .retain(|_, operation| operation != id);
    journal
        .target_approval_index
        .retain(|_, operation| operation != id);
    journal
        .independent_approval_index
        .retain(|_, operation| operation != id);
    journal
        .reconciliation_index
        .retain(|_, operation| operation != id);
    Ok(())
}

pub(super) fn terminal(
    id: &str,
    prepared: &mut PreparedOperationsV1,
    fresh: &mut FreshUvAttemptsV1,
    journal: &mut OperationJournalV1,
    now: u64,
) -> Result<(), crate::AgentError> {
    let record = journal
        .cancellations
        .get(id)
        .cloned()
        .ok_or(crate::AgentError::AuthorityRollback)?;
    operation(id, prepared, fresh, journal, now)?;
    crate::retired_request_retire_cancel::retire(journal, &record, now)?;
    let removed = journal
        .cancellations
        .remove(id)
        .ok_or(crate::AgentError::AuthorityRollback)?;
    let request = removed.browser_request.request_id;
    if journal.cancellation_index.remove(&request).as_deref() != Some(id) {
        return Err(crate::AgentError::AuthorityRollback);
    }
    Ok(())
}
