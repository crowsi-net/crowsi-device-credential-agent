use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementRequestV2, management_command_digest,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn load(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<Option<ReconcileRecordV1>, AgentError> {
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state
        .transaction_namespaces(|values| {
            let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
            let mut changed = crate::reconcile_state_tombstone::prune(&mut journal, now)?;
            let outcome =
                if crate::reconcile_state_tombstone::replayed(&journal, &browser.request_id) {
                    Load::Replay
                } else if let Some(key) = journal
                    .reconciliation_index
                    .get(&browser.request_id)
                    .cloned()
                {
                    if crate::reconcile_state_tombstone::abandon_expired(&mut journal, &key, now)? {
                        changed = true;
                        Load::Replay
                    } else {
                        let value = crate::reconcile_state::resume(&key, &journal)?;
                        if crate::reconcile_state::exact_retry(&value, browser, &digest) {
                            Load::Value(value)
                        } else {
                            Load::Replay
                        }
                    }
                } else {
                    Load::Absent
                };
            if changed {
                source_options_state::validate(&prepared, &fresh, &journal)?;
                values.put("operation-journal", &journal)?;
            }
            Ok((outcome, changed))
        })
        .and_then(|outcome| match outcome {
            Load::Value(value) => Ok(Some(value)),
            Load::Absent => Ok(None),
            Load::Replay => Err(AgentError::OperationReplay),
        })
}

enum Load {
    Value(ReconcileRecordV1),
    Absent,
    Replay,
}

pub(crate) fn reserve(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    current: &AuthorityRequestV1,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    let ManagementCommandV2::Reconcile { operation_id, .. } = &browser.command else {
        return Err(AgentError::RequestInvalid);
    };
    crate::current_request_validation::exact(current, None)?;
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        crate::reconcile_state_tombstone::prune(&mut journal, now)?;
        abandon_stale(&mut journal, operation_id, now)?;
        if crate::source_options_state_indexes::request_exists(&journal, &browser.request_id)
            || active_operation(&journal, operation_id)
        {
            return Err(AgentError::OperationReplay);
        }
        crate::reconcile_state_tombstone::make_room(&mut journal, now)?;
        let mut record = ReconcileRecordV1 {
            operation_id: operation_id.clone(),
            browser_request: browser.clone(),
            browser_request_digest_sha256: digest.clone(),
            phase: ReconcilePhaseV1::CurrentPrepared,
            current_request: current.clone(),
            current_exchange: None,
            current_observed_at_epoch_s: None,
            lookup_request: None,
            lookup_response_json: None,
            lookup_response: None,
            central_envelope_json: None,
            central_envelope: None,
            response_json: None,
            response: None,
            expires_at_epoch_s: 0,
            retain_until_epoch_s: 0,
            updated_at_epoch_s: now,
        };
        record.expires_at_epoch_s = crate::reconcile_state::expiration(&record)?;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::IdentityUnavailable);
        }
        journal
            .reconciliation_index
            .insert(browser.request_id.clone(), digest.clone());
        journal
            .reconciliations
            .insert(digest.clone(), Box::new(record));
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::reconcile_state::resume(&digest, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn active_operation(
    journal: &crate::source_options_state_types::OperationJournalV1,
    operation: &str,
) -> bool {
    journal
        .reconciliations
        .values()
        .any(|value| value.operation_id == operation && value.phase != ReconcilePhaseV1::Complete)
}

fn abandon_stale(
    journal: &mut crate::source_options_state_types::OperationJournalV1,
    operation: &str,
    now: u64,
) -> Result<(), AgentError> {
    let keys: Vec<_> = journal
        .reconciliations
        .iter()
        .filter(|(_, value)| value.operation_id == operation)
        .map(|(key, _)| key.clone())
        .collect();
    for key in keys {
        crate::reconcile_state_tombstone::abandon_expired(journal, &key, now)?;
    }
    Ok(())
}
