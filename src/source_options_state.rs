use crate::{AgentError, replay_namespace::SecurityNamespaces};

use crate::source_options_state_types::{
    FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1,
};
pub(super) use crate::source_options_state_types::{SourceOptionsPhaseV1, SourceOptionsResume};

pub(super) const MAXIMUM_SOURCE_OPERATIONS: usize = 4;
pub(super) const MAXIMUM_PHASE_WIRE_BYTES: usize = 49_152;

pub(super) fn documents(
    values: &SecurityNamespaces,
) -> Result<(PreparedOperationsV1, FreshUvAttemptsV1, OperationJournalV1), AgentError> {
    let prepared = values
        .get("prepared-operation")?
        .unwrap_or_else(PreparedOperationsV1::empty);
    let fresh = values
        .get("fresh-uv-attempt")?
        .unwrap_or_else(FreshUvAttemptsV1::empty);
    let journal = values
        .get("operation-journal")?
        .unwrap_or_else(OperationJournalV1::empty);
    validate(&prepared, &fresh, &journal)?;
    Ok((prepared, fresh, journal))
}

pub(super) fn validate(
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<(), AgentError> {
    let exact = prepared.schema == "crowsi://device-agent/prepared-operations/v3"
        && fresh.schema == "crowsi://device-agent/fresh-uv-attempts/v2"
        && journal.schema == "crowsi://device-agent/operation-journal/v5"
        && prepared.records.len() <= MAXIMUM_SOURCE_OPERATIONS
        && fresh.records.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.records.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.request_index.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.source_approvals.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.source_approval_index.len() <= MAXIMUM_SOURCE_OPERATIONS
        && prepared.actor_records.len() <= MAXIMUM_SOURCE_OPERATIONS
        && fresh.actor_records.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.actor_options.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.actor_options_index.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.cancellations.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.cancellation_index.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.cancel_request_tombstones.len() <= 16
        && journal.target_approvals.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.target_approval_index.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.independent_approvals.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.independent_approval_index.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.reconciliations.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.reconciliation_index.len() <= MAXIMUM_SOURCE_OPERATIONS
        && journal.reconcile_request_tombstones.len() <= 16
        && journal.retired_request_receipts.len() <= 32
        && prepared.records.keys().eq(fresh.records.keys())
        && prepared.records.keys().eq(journal.records.keys())
        && prepared
            .records
            .iter()
            .all(|(id, value)| value.prepared.operation_id == *id)
        && fresh
            .records
            .iter()
            .all(|(id, value)| value.operation_id == *id)
        && journal.records.iter().all(|(id, value)| {
            prepared.records.get(id).is_some_and(|prepared| {
                fresh.records.get(id).is_some_and(|fresh| {
                    crate::source_options_state_validation::record(id, prepared, fresh, value)
                        .is_ok()
                })
            })
        })
        && journal.request_index.iter().all(|(request, operation)| {
            journal.records.get(operation).is_some_and(|value| {
                value.browser_request_id == *request
                    && prepared
                        .records
                        .get(operation)
                        .is_some_and(|prepared| prepared.browser_request.request_id == *request)
            })
        });
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)?;
    crate::source_approve_state_validation::all(prepared, fresh, journal)?;
    crate::actor_options_state_validation::all(prepared, fresh, journal)?;
    crate::cancel_state_validation::all(journal)?;
    crate::target_approve_state_validation::all(prepared, fresh, journal)?;
    crate::independent_approve_state_validation::all(prepared, fresh, journal)?;
    crate::reconcile_state_validation::all(journal)?;
    crate::retired_request_validation::all(journal)?;
    crate::source_options_state_indexes::unique(journal)
}

pub(super) fn resume(
    operation: &str,
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<SourceOptionsResume, AgentError> {
    Ok(SourceOptionsResume {
        prepared: prepared
            .records
            .get(operation)
            .cloned()
            .map(Box::new)
            .ok_or(AgentError::AuthorityRollback)?,
        fresh_uv: fresh
            .records
            .get(operation)
            .cloned()
            .map(Box::new)
            .ok_or(AgentError::AuthorityRollback)?,
        journal: journal
            .records
            .get(operation)
            .cloned()
            .map(Box::new)
            .ok_or(AgentError::AuthorityRollback)?,
    })
}

pub(super) fn digest(domain: &str, value: &impl serde::Serialize) -> Result<String, AgentError> {
    let value = serde_json::to_value(value).map_err(|_| AgentError::RequestInvalid)?;
    let wire = crate::crypto::canonical_signed_document(domain, &value)?;
    Ok(crate::crypto::digest(&wire))
}
