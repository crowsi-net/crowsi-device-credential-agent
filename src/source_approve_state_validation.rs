use crowsi_credential_authority_contracts::{ManagementCommandV2, management_command_digest};
use ihat_identity_assertion_contracts::{AuthorityCommand, decode_authority_request_strict};

use crate::{
    AgentError,
    source_approve_state_types::SourceApproveRecordV1,
    source_options_state::SourceOptionsPhaseV1,
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

pub(super) fn all(
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<(), AgentError> {
    let indexes = journal
        .source_approval_index
        .iter()
        .all(|(request, operation)| {
            journal
                .source_approvals
                .get(operation)
                .is_some_and(|value| value.browser_request.request_id == *request)
        });
    let records = journal
        .source_approvals
        .iter()
        .all(|(operation, value)| record(operation, value, prepared, fresh, journal).is_ok());
    (indexes && records)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn record(
    operation: &str,
    value: &SourceApproveRecordV1,
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<(), AgentError> {
    let source = prepared
        .records
        .get(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    let selected = fresh
        .records
        .get(operation)
        .and_then(|value| value.exchange.as_ref())
        .ok_or(AgentError::AuthorityRollback)?;
    let source_journal = journal
        .records
        .get(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    let digest = management_command_digest(&value.browser_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let ManagementCommandV2::SourceApprove {
        operation_id,
        expected_state_revision,
        ..
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let base = value.operation_id == operation
        && operation_id == operation
        && *expected_state_revision == 1
        && value.browser_request_digest_sha256 == digest
        && source_journal.phase == SourceOptionsPhaseV1::Complete
        && value.expires_at_epoch_s == crate::source_approve_state::expiration(selected, value)?
        && (value.updated_at_epoch_s <= value.expires_at_epoch_s
            || crate::source_approve_state_finalization::historic(value));
    let observation = value.current_observed_at_epoch_s.is_none_or(|observed| {
        value.current_exchange.as_ref().is_some_and(|current| {
            current.response.issued_at_epoch_s <= observed
                && observed <= value.updated_at_epoch_s
                && observed < value.expires_at_epoch_s
        })
    });
    if !base
        || !observation
        || !finish(value)?
        || crate::source_approve_state_reservation_validation::valid(value, source).is_err()
        || !crate::source_approve_state_phase_validation::valid(value)
        || crate::source_approve_state_revocation::validate(value, &source.prepared).is_err()
    {
        return Err(AgentError::AuthorityRollback);
    }
    crate::source_approve_state_wire::validate(value, source)
}

fn finish(value: &SourceApproveRecordV1) -> Result<bool, AgentError> {
    let wire =
        serde_json::to_vec(&value.finish_request).map_err(|_| AgentError::AuthorityRollback)?;
    let request =
        decode_authority_request_strict(&wire).map_err(|_| AgentError::AuthorityRollback)?;
    let AuthorityCommand::FinishFreshUserVerification(command) = &request.command else {
        return Ok(false);
    };
    let ManagementCommandV2::SourceApprove {
        attempt_id,
        assertion,
        ..
    } = &value.browser_request.command
    else {
        return Ok(false);
    };
    let exact = request == value.finish_request
        && request.evidence.is_empty()
        && command.attempt_id == *attempt_id
        && command.credential_id == assertion.credential_id
        && command.client_data_json_base64url == assertion.client_data_json_base64url
        && command.authenticator_data_base64url == assertion.authenticator_data_base64url
        && command.signature_der_base64url == assertion.signature_der_base64url
        && value
            .finish_exchange
            .as_ref()
            .is_none_or(|exchange| exchange.request == request);
    Ok(exact)
}
