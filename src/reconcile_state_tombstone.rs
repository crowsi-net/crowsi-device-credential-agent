use crate::{
    AgentError,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRequestTombstoneV1},
    source_options_state_types::OperationJournalV1,
};

const RETENTION_SECONDS: u64 = 600;
const MAXIMUM_TOMBSTONES: usize = 16;

pub(super) fn prune(value: &mut OperationJournalV1, now: u64) -> Result<bool, AgentError> {
    let before = value.reconcile_request_tombstones.len();
    value
        .reconcile_request_tombstones
        .retain(|_, item| now < item.retain_until_epoch_s);
    let expired: Vec<_> = value
        .reconciliations
        .iter()
        .filter(|(_, item)| {
            item.phase == ReconcilePhaseV1::Complete && now >= item.retain_until_epoch_s
        })
        .map(|(key, _)| key.clone())
        .collect();
    let mut changed = before != value.reconcile_request_tombstones.len();
    for key in expired {
        tombstone(value, &key, now)?;
        changed = true;
    }
    Ok(changed)
}

pub(super) fn abandon_expired(
    value: &mut OperationJournalV1,
    key: &str,
    now: u64,
) -> Result<bool, AgentError> {
    let Some(record) = value.reconciliations.get(key) else {
        return Ok(false);
    };
    let safe = now >= record.expires_at_epoch_s
        && !crate::reconcile_state::central_ambiguous(record)
        && record.phase != ReconcilePhaseV1::Complete;
    if safe {
        tombstone(value, key, now)?;
    }
    Ok(safe)
}

pub(super) fn make_room(value: &mut OperationJournalV1, now: u64) -> Result<(), AgentError> {
    if value.reconciliations.len() < crate::source_options_state::MAXIMUM_SOURCE_OPERATIONS {
        return Ok(());
    }
    let oldest = value
        .reconciliations
        .iter()
        .filter(|(_, item)| item.phase == ReconcilePhaseV1::Complete)
        .min_by_key(|(_, item)| item.updated_at_epoch_s)
        .map(|(key, _)| key.clone())
        .or_else(|| {
            value
                .reconciliations
                .iter()
                .filter(|(_, item)| {
                    now >= item.expires_at_epoch_s
                        && !crate::reconcile_state::central_ambiguous(item)
                })
                .min_by_key(|(_, item)| item.updated_at_epoch_s)
                .map(|(key, _)| key.clone())
        })
        .ok_or(AgentError::AuthorityUnavailable)?;
    tombstone(value, &oldest, now)
}

fn tombstone(value: &mut OperationJournalV1, key: &str, now: u64) -> Result<(), AgentError> {
    if value.reconcile_request_tombstones.len() >= MAXIMUM_TOMBSTONES {
        return Err(AgentError::AuthorityUnavailable);
    }
    let record = value
        .reconciliations
        .remove(key)
        .ok_or(AgentError::AuthorityRollback)?;
    let request = record.browser_request.request_id;
    if value.reconciliation_index.remove(&request).as_deref() != Some(key) {
        return Err(AgentError::AuthorityRollback);
    }
    let item = ReconcileRequestTombstoneV1 {
        browser_request_digest_sha256: record.browser_request_digest_sha256,
        operation_id: record.operation_id,
        expired_at_epoch_s: now,
        retain_until_epoch_s: now
            .checked_add(RETENTION_SECONDS)
            .ok_or(AgentError::AuthorityRollback)?,
    };
    if value
        .reconcile_request_tombstones
        .insert(request, item)
        .is_some()
    {
        return Err(AgentError::AuthorityRollback);
    }
    Ok(())
}

pub(super) fn validate(value: &OperationJournalV1) -> Result<(), AgentError> {
    let exact = value.reconcile_request_tombstones.len() <= MAXIMUM_TOMBSTONES
        && value
            .reconcile_request_tombstones
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

pub(super) fn replayed(value: &OperationJournalV1, request: &str) -> bool {
    value.reconcile_request_tombstones.contains_key(request)
}
