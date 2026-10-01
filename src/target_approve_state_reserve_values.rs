use crowsi_credential_authority_contracts::{ManagementCommandV2, ManagementRequestV2};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
    target_approve_state_types::{
        TargetApprovePhaseV1, TargetApproveRecordV1, TargetApproveResume,
    },
};

pub(super) fn command(value: &ManagementRequestV2) -> Result<(&str, u64, &str, &str), AgentError> {
    let ManagementCommandV2::TargetApprove {
        operation_id,
        expected_state_revision,
        attempt_id,
        assertion,
    } = &value.command
    else {
        return Err(AgentError::RequestInvalid);
    };
    Ok((
        operation_id,
        *expected_state_revision,
        attempt_id,
        &assertion.credential_id,
    ))
}

pub(super) fn initial(
    operation: &str,
    browser: &ManagementRequestV2,
    digest: String,
    finish: &AuthorityRequestV1,
    now: u64,
) -> TargetApproveRecordV1 {
    TargetApproveRecordV1 {
        operation_id: operation.into(),
        browser_request: browser.clone(),
        browser_request_digest_sha256: digest,
        phase: TargetApprovePhaseV1::FinishPrepared,
        finish_request: finish.clone(),
        finish_exchange: None,
        current_request: None,
        current_exchange: None,
        current_observed_at_epoch_s: None,
        pa_request_json: None,
        pa_request: None,
        pa_response_json: None,
        pa_response: None,
        custody_response_json: None,
        custody_response: None,
        target_proof: None,
        central_envelope_json: None,
        central_envelope: None,
        response_json: None,
        response: None,
        expires_at_epoch_s: 0,
        updated_at_epoch_s: now,
    }
}

pub(super) fn resume_shell(
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
    approval: TargetApproveRecordV1,
    operation: &str,
) -> Result<TargetApproveResume, AgentError> {
    let actor = journal
        .actor_options
        .get(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    Ok(TargetApproveResume {
        selected_identity: actor
            .current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        selected_begin: fresh
            .actor_records
            .get(operation)
            .and_then(|value| value.exchange.clone())
            .ok_or(AgentError::AuthorityRollback)?,
        lookup: prepared
            .actor_records
            .get(operation)
            .cloned()
            .ok_or(AgentError::AuthorityRollback)?,
        actor_projection: actor
            .response
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        approval: Box::new(approval),
    })
}
