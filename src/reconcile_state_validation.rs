use crowsi_credential_authority_contracts::{ManagementCommandV2, management_command_digest};

use crate::{
    AgentError,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    source_options_state_types::OperationJournalV1,
};

pub(super) fn all(journal: &OperationJournalV1) -> Result<(), AgentError> {
    crate::reconcile_state_tombstone::validate(journal)?;
    let indexes = journal.reconciliation_index.len() == journal.reconciliations.len()
        && journal.reconciliation_index.iter().all(|(request, key)| {
            journal.reconciliations.get(key).is_some_and(|value| {
                value.browser_request.request_id == *request
                    && value.browser_request_digest_sha256 == *key
            })
        });
    let records = journal
        .reconciliations
        .iter()
        .all(|(key, value)| record(key, value).is_ok());
    (indexes && records)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn record(key: &str, value: &ReconcileRecordV1) -> Result<(), AgentError> {
    let digest = management_command_digest(&value.browser_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let ManagementCommandV2::Reconcile {
        operation_id,
        expected_state_revision,
        ..
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let historic = crate::reconcile_state::central_ambiguous(value)
        || value.phase == ReconcilePhaseV1::Complete;
    let retention = if value.phase == ReconcilePhaseV1::Complete {
        value.updated_at_epoch_s.checked_add(600) == Some(value.retain_until_epoch_s)
    } else {
        value.retain_until_epoch_s == 0
    };
    let exact = key == digest
        && key == value.browser_request_digest_sha256
        && operation_id == &value.operation_id
        && *expected_state_revision > 0
        && value.expires_at_epoch_s == crate::reconcile_state::expiration(value)?
        && (value.updated_at_epoch_s <= value.expires_at_epoch_s || historic)
        && retention
        && phase(value);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)?;
    crate::reconcile_state_wire::exact(value)
}

fn phase(value: &ReconcileRecordV1) -> bool {
    use ReconcilePhaseV1 as P;
    let current = value.current_exchange.is_some();
    let observed = value.current_observed_at_epoch_s.is_some();
    let lookup_request = value.lookup_request.is_some();
    let lookup = value.lookup_response.is_some() && value.lookup_response_json.is_some();
    let envelope = value.central_envelope.is_some() && value.central_envelope_json.is_some();
    let response = value.response.is_some() && value.response_json.is_some();
    match value.phase {
        P::CurrentPrepared | P::CurrentInvoking | P::CurrentUnknown => {
            !current && !observed && !lookup_request && !lookup && !envelope && !response
        }
        P::CurrentObservePrepared | P::CurrentObserveInvoking | P::CurrentObserveUnknown => {
            current && !observed && !lookup_request && !lookup && !envelope && !response
        }
        P::LookupPrepared | P::LookupInvoking | P::LookupUnknown => {
            current && observed && lookup_request && !lookup && !envelope && !response
        }
        P::CentralPrepared | P::CentralInvoking | P::Unknown => {
            current && observed && lookup_request && lookup && envelope && !response
        }
        P::Complete => current && observed && lookup_request && lookup && envelope && response,
    }
}
