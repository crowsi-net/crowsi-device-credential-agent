use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1 as P, CancelRecordV1},
    source_options_state,
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

const NAMESPACE_BYTES: u64 = 131_072;
pub(super) const PHASE_IMAGE_BYTES: u64 =
    (source_options_state::MAXIMUM_PHASE_WIRE_BYTES as u64) * 2;

pub(super) struct Checkpoint {
    materialized: u64,
    reserved: u64,
}

pub(super) fn reserve(value: &mut CancelRecordV1) {
    value.future_bytes_reserved = PHASE_IMAGE_BYTES;
}

pub(super) fn checkpoint(value: &CancelRecordV1) -> Result<Checkpoint, AgentError> {
    Ok(Checkpoint {
        materialized: materialized(value)?,
        reserved: value.future_bytes_reserved,
    })
}

pub(super) fn rebalance(value: &mut CancelRecordV1, before: Checkpoint) -> Result<(), AgentError> {
    let high_water = before
        .materialized
        .checked_add(before.reserved)
        .ok_or(AgentError::AuthorityUnavailable)?;
    let after = materialized(value)?;
    value.future_bytes_reserved = remaining(high_water, after)?;
    Ok(())
}

pub(super) fn admit(
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
    now: u64,
) -> Result<(), AgentError> {
    let mut prepared = prepared.clone();
    let mut fresh = fresh.clone();
    let mut journal = journal.clone();
    let operations = journal
        .cancellations
        .iter()
        .filter(|(_, record)| deferred(record))
        .map(|(operation, _)| operation.clone())
        .collect::<Vec<_>>();
    for operation in operations {
        crate::cancel_state_cleanup::operation(
            &operation,
            &mut prepared,
            &mut fresh,
            &mut journal,
            now,
        )?;
    }
    capacity(&journal, true)
        .then_some(())
        .ok_or(AgentError::AuthorityUnavailable)
}

pub(super) fn validate(value: &OperationJournalV1) -> Result<(), AgentError> {
    capacity(value, false)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn within(value: &OperationJournalV1) -> bool {
    capacity(value, false)
}

fn capacity(value: &OperationJournalV1, include_deferred: bool) -> bool {
    if !value
        .cancellations
        .values()
        .all(|record| crate::cancel_state_capacity_image::valid(record))
    {
        return false;
    }
    let Ok(actual) = serde_json::to_vec(value).map(|wire| wire.len() as u64) else {
        return false;
    };
    let reserved = value.cancellations.values().try_fold(0_u64, |total, item| {
        let reserve = if include_deferred || !deferred(item) {
            item.future_bytes_reserved
        } else {
            0
        };
        total.checked_add(reserve)
    });
    reserved.is_some_and(|reserved| fits(actual, reserved))
}

fn deferred(value: &CancelRecordV1) -> bool {
    value.future_bytes_reserved > 0
        && matches!(
            value.phase,
            P::CentralPrepared | P::CentralInvoking | P::Unknown
        )
}

fn materialized(value: &CancelRecordV1) -> Result<u64, AgentError> {
    let mut value = value.clone();
    value.future_bytes_reserved = 0;
    serde_json::to_vec(&value)
        .map(|wire| wire.len() as u64)
        .map_err(|_| AgentError::AuthorityRollback)
}

fn remaining(high_water: u64, actual: u64) -> Result<u64, AgentError> {
    high_water
        .checked_sub(actual)
        .map(|value| value.min(PHASE_IMAGE_BYTES))
        .ok_or(AgentError::AuthorityUnavailable)
}

fn fits(actual: u64, reserved: u64) -> bool {
    actual
        .checked_add(reserved)
        .is_some_and(|total| total <= NAMESPACE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::{PHASE_IMAGE_BYTES, fits, remaining};

    #[test]
    fn one_byte_short_is_rejected_before_the_cancel_commit() {
        assert!(fits(32_768, PHASE_IMAGE_BYTES));
        assert!(!fits(32_769, PHASE_IMAGE_BYTES));
    }

    #[test]
    fn compaction_credits_the_next_two_artifact_image() {
        let high = 20_000 + PHASE_IMAGE_BYTES;
        assert_eq!(remaining(high, 69_152), Ok(49_152));
        assert_eq!(remaining(high, 20_000), Ok(PHASE_IMAGE_BYTES));
    }

    #[test]
    fn aggregate_reservations_share_one_namespace_limit() {
        assert!(fits(32_768, 4 * 24_576));
        assert!(!fits(32_769, 4 * 24_576));
    }
}
