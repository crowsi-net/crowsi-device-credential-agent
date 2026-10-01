use crate::{
    AgentError,
    source_options_state::{self, SourceOptionsPhaseV1},
    source_options_state_types::{
        FreshUvAttemptV1, PreparedSourceOptionsV1, SourceOptionsJournalRecordV1,
    },
};
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, decode_endpoint_management_envelope_strict,
    decode_management_projection_strict, endpoint_operation_digest,
    identity_evidence_from_exchange, management_command_digest,
};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityResult, ResponseOutcome, decode_authority_request_strict,
};
pub(super) fn record(
    operation: &str,
    prepared: &PreparedSourceOptionsV1,
    fresh: &FreshUvAttemptV1,
    journal: &SourceOptionsJournalRecordV1,
) -> Result<(), AgentError> {
    let browser_digest = management_command_digest(&prepared.browser_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = prepared.prepared.operation_id == operation
        && prepared.prepared.origin_command_digest_sha256 == browser_digest
        && prepared.browser_request_digest_sha256 == browser_digest
        && fresh.operation_id == operation
        && journal.operation_id == operation
        && journal.browser_request_id == prepared.browser_request.request_id
        && journal.browser_request_digest_sha256 == browser_digest
        && journal.expires_at_epoch_s == expiration(prepared, fresh)?
        && (journal.updated_at_epoch_s <= journal.expires_at_epoch_s
            || crate::fresh_uv_options::source_historic(
                journal.phase,
                fresh,
                journal.updated_at_epoch_s,
            )?);
    if !exact
        || crate::source_options_scope_validation::valid(prepared).is_err()
        || !begin(prepared, fresh)?
        || !phase(fresh, journal)
    {
        return Err(AgentError::AuthorityRollback);
    }
    envelope(prepared, fresh, journal)?;
    response(journal)
}
pub(super) fn expiration(
    prepared: &PreparedSourceOptionsV1,
    fresh: &FreshUvAttemptV1,
) -> Result<u64, AgentError> {
    let identity = identity_evidence_from_exchange(&prepared.selected_identity_exchange)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let mut expires = prepared
        .prepared
        .expires_at_epoch_s
        .min(
            prepared
                .selected_identity_exchange
                .response
                .expires_at_epoch_s,
        )
        .min(identity.assertion.expires_at_epoch_s)
        .min(identity.current_status.expires_at_epoch_s);
    if let Some(exchange) = &fresh.exchange {
        let ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options),
        } = &exchange.response.outcome
        else {
            return Err(AgentError::AuthorityRollback);
        };
        expires = expires
            .min(exchange.response.expires_at_epoch_s)
            .min(options.expires_at_epoch_s);
    }
    Ok(expires)
}
fn begin(prepared: &PreparedSourceOptionsV1, fresh: &FreshUvAttemptV1) -> Result<bool, AgentError> {
    let wire = serde_json::to_vec(&fresh.request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded =
        decode_authority_request_strict(&wire).map_err(|_| AgentError::AuthorityRollback)?;
    let AuthorityCommand::BeginFreshUserVerification(command) = &fresh.request.command else {
        return Ok(false);
    };
    let identity = identity_evidence_from_exchange(&prepared.selected_identity_exchange)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let epochs = &identity.assertion.revocation_epochs;
    Ok(decoded == fresh.request
        && fresh.request.evidence.is_empty()
        && command.identity_nonce == identity.assertion.nonce
        && command.source_device_id == identity.assertion.device_id
        && command.service_id == identity.assertion.service_id
        && command.pairwise_subject == identity.assertion.pairwise_subject
        && command.session_ref == identity.assertion.session_ref
        && command.subject_epoch == epochs.subject
        && command.service_epoch == epochs.service
        && command.device_epoch == epochs.device
        && command.session_epoch == epochs.session
        && command.operation_digest_sha256
            == endpoint_operation_digest(&prepared.prepared)
                .map_err(|_| AgentError::AuthorityRollback)?)
}
fn phase(fresh: &FreshUvAttemptV1, journal: &SourceOptionsJournalRecordV1) -> bool {
    let envelope =
        journal.central_envelope_json.is_some() && journal.central_envelope_digest_sha256.is_some();
    let response = journal.response_json.is_some() && journal.response.is_some();
    match journal.phase {
        SourceOptionsPhaseV1::BeginPrepared => fresh.exchange.is_none() && !envelope && !response,
        SourceOptionsPhaseV1::CentralPrepared
        | SourceOptionsPhaseV1::CentralInvoking
        | SourceOptionsPhaseV1::Unknown => fresh.exchange.is_some() && envelope && !response,
        SourceOptionsPhaseV1::Complete => fresh.exchange.is_some() && envelope && response,
    }
}
fn envelope(
    prepared: &PreparedSourceOptionsV1,
    fresh: &FreshUvAttemptV1,
    journal: &SourceOptionsJournalRecordV1,
) -> Result<(), AgentError> {
    let Some(wire) = journal.central_envelope_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_endpoint_management_envelope_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let digest = source_options_state::digest("CROWSI-ENDPOINT-CENTRAL-ENVELOPE-V2", &decoded)?;
    let exact = decoded.browser_request == prepared.browser_request
        && matches!(
            &decoded.evidence,
            EndpointManagementEvidenceV2::SourceOptions {
                identity_exchange,
                prepared: operation,
                uv_options,
            } if identity_exchange == &prepared.selected_identity_exchange
                && operation == &prepared.prepared
                && Some(uv_options) == fresh.exchange.as_ref()
        )
        && journal.central_envelope_digest_sha256.as_deref() == Some(digest.as_str());
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
fn response(journal: &SourceOptionsJournalRecordV1) -> Result<(), AgentError> {
    let Some(wire) = journal.response_json.as_deref() else {
        return Ok(());
    };
    let value = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (journal.response.as_ref() == Some(&value))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
