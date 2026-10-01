use std::collections::BTreeSet;

use crate::{AgentError, source_options_state_types::OperationJournalV1};

pub(super) fn unique(journal: &OperationJournalV1) -> Result<(), AgentError> {
    let indexes = [
        &journal.request_index,
        &journal.source_approval_index,
        &journal.actor_options_index,
        &journal.cancellation_index,
        &journal.target_approval_index,
        &journal.independent_approval_index,
        &journal.reconciliation_index,
    ];
    let expected: usize = indexes.iter().map(|index| index.len()).sum::<usize>()
        + journal.cancel_request_tombstones.len()
        + journal.reconcile_request_tombstones.len()
        + journal.retired_request_receipts.len();
    let mut requests = indexes
        .into_iter()
        .flat_map(|index| index.keys())
        .collect::<BTreeSet<_>>();
    requests.extend(journal.cancel_request_tombstones.keys());
    requests.extend(journal.reconcile_request_tombstones.keys());
    requests.extend(journal.retired_request_receipts.keys());
    (requests.len() == expected)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn request_exists(journal: &OperationJournalV1, request: &str) -> bool {
    journal.request_index.contains_key(request)
        || journal.source_approval_index.contains_key(request)
        || journal.actor_options_index.contains_key(request)
        || journal.cancellation_index.contains_key(request)
        || journal.target_approval_index.contains_key(request)
        || journal.independent_approval_index.contains_key(request)
        || journal.cancel_request_tombstones.contains_key(request)
        || journal.reconciliation_index.contains_key(request)
        || journal.reconcile_request_tombstones.contains_key(request)
        || journal.retired_request_receipts.contains_key(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cancel_state_types::CancelRequestTombstoneV1,
        source_options_state_types::{FreshUvAttemptsV1, PreparedOperationsV1},
    };

    #[test]
    fn request_indexes_are_pairwise_disjoint() {
        let mut journal = OperationJournalV1::empty();
        journal
            .request_index
            .insert("browser-a".into(), "op-a".into());
        journal
            .cancellation_index
            .insert("browser-b".into(), "op-b".into());
        unique(&journal).expect("unique request ids");
        journal
            .cancellation_index
            .insert("browser-a".into(), "op-b".into());
        assert_eq!(unique(&journal), Err(AgentError::AuthorityRollback));
    }

    #[test]
    fn cancel_tombstones_are_closed_and_bounded() {
        let mut journal = OperationJournalV1::empty();
        for index in 0..16 {
            journal
                .cancel_request_tombstones
                .insert(format!("cancel-request-{index}"), tombstone(index));
        }
        crate::source_options_state::validate(
            &PreparedOperationsV1::empty(),
            &FreshUvAttemptsV1::empty(),
            &journal,
        )
        .expect("sixteen retained tombstones");
        journal
            .cancel_request_tombstones
            .insert("cancel-request-16".into(), tombstone(16));
        assert_eq!(
            crate::source_options_state::validate(
                &PreparedOperationsV1::empty(),
                &FreshUvAttemptsV1::empty(),
                &journal,
            ),
            Err(AgentError::AuthorityRollback)
        );
    }

    fn tombstone(index: usize) -> CancelRequestTombstoneV1 {
        CancelRequestTombstoneV1 {
            browser_request_digest_sha256: "a".repeat(64),
            operation_id: format!("{index:064x}"),
            expired_at_epoch_s: 100,
            retain_until_epoch_s: 700,
        }
    }
}
