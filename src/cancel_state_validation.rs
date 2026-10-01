use crowsi_credential_authority_contracts::{ManagementCommandV2, management_command_digest};

use crate::{
    AgentError,
    cancel_state_types::CancelRecordV1,
    source_options_state_types::OperationJournalV1,
};

pub(super) fn all(journal: &OperationJournalV1) -> Result<(), AgentError> {
    crate::cancel_state_tombstone::validate(journal)?;
    crate::cancel_state_capacity::validate(journal)?;
    let indexes = journal.cancellation_index.len() == journal.cancellations.len()
        && journal
            .cancellation_index
            .iter()
            .all(|(request, operation)| {
                journal
                    .cancellations
                    .get(operation)
                    .is_some_and(|value| value.browser_request.request_id == *request)
            });
    let records = journal
        .cancellations
        .iter()
        .all(|(operation, value)| record(operation, value).is_ok());
    (indexes && records)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn record(operation: &str, value: &CancelRecordV1) -> Result<(), AgentError> {
    let digest = management_command_digest(&value.browser_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let ManagementCommandV2::Cancel {
        operation_id,
        expected_state_revision,
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let historic = crate::cancel_state::can_resume_expired(value);
    let base = operation == value.operation_id
        && operation_id == operation
        && *expected_state_revision > 0
        && value.browser_request_digest_sha256 == digest
        && value.expires_at_epoch_s == crate::cancel_state::expiration(value)?
        && (value.updated_at_epoch_s <= value.expires_at_epoch_s || historic);
    let observation = value.current_observed_at_epoch_s.is_none_or(|observed| {
        value.current_exchange.as_ref().is_some_and(|current| {
            current.response.issued_at_epoch_s <= observed
                && observed <= value.updated_at_epoch_s
                && observed < value.expires_at_epoch_s
        })
    });
    if !base || !observation || !crate::cancel_state_phase_validation::valid(value) {
        return Err(AgentError::AuthorityRollback);
    }
    crate::cancel_state_wire::exact(value)
}
