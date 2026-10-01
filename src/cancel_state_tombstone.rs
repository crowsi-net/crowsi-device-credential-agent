use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1, CancelRequestTombstoneV1},
    source_options_state_types::OperationJournalV1,
};

const RETENTION_SECONDS: u64 = 600;
const MAXIMUM_TOMBSTONES: usize = 16;

pub(super) fn prune(value: &mut OperationJournalV1, now: u64) -> bool {
    let before = value.cancel_request_tombstones.len();
    value
        .cancel_request_tombstones
        .retain(|_, item| now < item.retain_until_epoch_s);
    before != value.cancel_request_tombstones.len()
}

pub(super) fn replayed(value: &OperationJournalV1, request: &str) -> bool {
    value.cancel_request_tombstones.contains_key(request)
}

pub(super) fn abandon(
    value: &mut OperationJournalV1,
    operation: &str,
    now: u64,
) -> Result<bool, AgentError> {
    let Some(record) = value.cancellations.get(operation) else {
        return Ok(false);
    };
    let safe = now >= record.expires_at_epoch_s
        && matches!(
            record.phase,
            CancelPhaseV1::CurrentPrepared
                | CancelPhaseV1::CurrentInvoking
                | CancelPhaseV1::CurrentUnknown
                | CancelPhaseV1::CurrentObservePrepared
                | CancelPhaseV1::CurrentObserveInvoking
                | CancelPhaseV1::CurrentObserveUnknown
                | CancelPhaseV1::LookupPrepared
                | CancelPhaseV1::CentralPrepared
        );
    if !safe {
        return Ok(false);
    }
    tombstone(value, operation, now)?;
    Ok(true)
}

pub(super) fn make_room(value: &mut OperationJournalV1, now: u64) -> Result<(), AgentError> {
    if value.cancellations.len() < crate::source_options_state::MAXIMUM_SOURCE_OPERATIONS {
        return Ok(());
    }
    let oldest = value
        .cancellations
        .iter()
        .filter(|(_, item)| item.phase == CancelPhaseV1::Complete)
        .min_by_key(|(_, item)| item.updated_at_epoch_s)
        .map(|(operation, _)| operation.clone())
        .ok_or(AgentError::AuthorityUnavailable)?;
    tombstone(value, &oldest, now)
}

fn tombstone(value: &mut OperationJournalV1, operation: &str, now: u64) -> Result<(), AgentError> {
    if value.cancel_request_tombstones.len() >= MAXIMUM_TOMBSTONES {
        return Err(AgentError::AuthorityUnavailable);
    }
    let record = value
        .cancellations
        .remove(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    let request = record.browser_request.request_id;
    if value.cancellation_index.remove(&request).as_deref() != Some(operation) {
        return Err(AgentError::AuthorityRollback);
    }
    let item = CancelRequestTombstoneV1 {
        browser_request_digest_sha256: record.browser_request_digest_sha256,
        operation_id: operation.into(),
        expired_at_epoch_s: now,
        retain_until_epoch_s: now
            .checked_add(RETENTION_SECONDS)
            .ok_or(AgentError::AuthorityRollback)?,
    };
    if value
        .cancel_request_tombstones
        .insert(request, item)
        .is_some()
    {
        return Err(AgentError::AuthorityRollback);
    }
    Ok(())
}

pub(super) fn validate(value: &OperationJournalV1) -> Result<(), AgentError> {
    let exact = value
        .cancel_request_tombstones
        .iter()
        .all(|(request, item)| {
            crate::validation::id(request, 128)
                && crate::validation::hex_key(&item.browser_request_digest_sha256)
                && crate::validation::hex_key(&item.operation_id)
                && item.expired_at_epoch_s > 0
                && item.expired_at_epoch_s.checked_add(RETENTION_SECONDS)
                    == Some(item.retain_until_epoch_s)
        });
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
