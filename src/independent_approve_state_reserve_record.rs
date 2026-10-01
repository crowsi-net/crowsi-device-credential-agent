use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementOperationState, ManagementProjectionBodyV2, ManagementRequestV2,
};
use ihat_identity_assertion_contracts::{AuthorityRequestV1, AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    actor_options_state_types::PreparedRevocationResponseTrustV1,
    independent_approve_state_types::{IndependentApprovePhaseV1, IndependentApproveRecordV1},
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

#[allow(clippy::too_many_arguments)]
pub(super) fn selected(
    operation: &str,
    revision: u64,
    attempt: &str,
    credential: &str,
    browser: &ManagementRequestV2,
    digest: String,
    finish: &AuthorityRequestV1,
    now: u64,
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<IndependentApproveRecordV1, AgentError> {
    let actor = journal
        .actor_options
        .get(operation)
        .ok_or(AgentError::OperationReplay)?;
    if journal.independent_approvals.contains_key(operation)
        || actor.phase != crate::actor_options_state_types::ActorOptionsPhaseV1::Complete
        || !matches!(
            actor.browser_request.command,
            ManagementCommandV2::ApprovalOptions { .. }
        )
    {
        return Err(AgentError::OperationReplay);
    }
    let ManagementProjectionBodyV2::Operation {
        operation: projected,
    } = &actor
        .response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?
        .body
    else {
        return Err(AgentError::AuthorityRollback);
    };
    if projected.operation_id != operation
        || projected.state_revision != revision
        || projected.state != ManagementOperationState::AwaitingApprovalUv
    {
        return Err(AgentError::RequestInvalid);
    }
    let begin = fresh
        .actor_records
        .get(operation)
        .and_then(|value| value.exchange.as_ref())
        .ok_or(AgentError::AuthorityRollback)?;
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        return Err(AgentError::AuthorityRollback);
    };
    if options.attempt_id != attempt || options.credential_id != credential {
        return Err(AgentError::RequestInvalid);
    }
    let lookup = prepared
        .actor_records
        .get(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    let begun = lookup
        .response
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let ceremony = crate::source_approve_revocation_response_begin::metadata(
        &lookup.response.prepared,
        begun,
    )?;
    if now >= ceremony.expires_at_epoch_s {
        return Err(AgentError::FreshUserVerificationRequired);
    }
    crate::actor_options_state_lookup_trust::valid(lookup)?;
    let pin = lookup
        .revocation_response_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    Ok(initial(operation, browser, digest, finish, pin, now))
}

fn initial(
    operation: &str,
    browser: &ManagementRequestV2,
    digest: String,
    finish: &AuthorityRequestV1,
    pin: &PreparedRevocationResponseTrustV1,
    now: u64,
) -> IndependentApproveRecordV1 {
    IndependentApproveRecordV1 {
        operation_id: operation.into(),
        browser_request: browser.clone(),
        browser_request_digest_sha256: digest,
        phase: IndependentApprovePhaseV1::FinishPrepared,
        finish_request: finish.clone(),
        finish_exchange: None,
        current_request: None,
        current_exchange: None,
        current_observed_at_epoch_s: None,
        approval_request_json: None,
        approval_request: None,
        approval_key_id: None,
        approval_key_fingerprint: None,
        approval_public_key_hex: None,
        approval_exchange: None,
        pre_final_request_json: None,
        pre_final_request: None,
        pre_final_response_json: None,
        pre_final_response: None,
        pre_final_trust: None,
        reservation_current_request: None,
        reservation_current_exchange: None,
        reservation_current_observed_at_epoch_s: None,
        execution_reserve_request_json: None,
        execution_reserve_request: None,
        execution_reservation_json: None,
        execution_reservation: None,
        execution_reservation_trust: None,
        final_request_json: None,
        final_request: None,
        final_exchange: None,
        finalize_request_json: None,
        finalize_request: None,
        response_key_id: pin.key_id.clone(),
        response_public_key_hex: pin.public_key_hex.clone(),
        response_minimum_generation: pin.minimum_config_generation,
        response_json: None,
        response: None,
        expires_at_epoch_s: 0,
        updated_at_epoch_s: now,
    }
}
