use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementOperationState, ManagementProjectionBodyV2,
    management_command_digest,
};
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    actor_options_state_types::ActorOptionsPhaseV1,
    independent_approve_state_types::IndependentApproveRecordV1,
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

pub(super) fn all(
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<(), AgentError> {
    let indexes = journal
        .independent_approval_index
        .iter()
        .all(|(request, operation)| {
            journal
                .independent_approvals
                .get(operation)
                .is_some_and(|value| {
                    value.browser_request.request_id == *request && value.operation_id == *operation
                })
        });
    let records = journal
        .independent_approvals
        .iter()
        .all(|(operation, value)| {
            journal
                .independent_approval_index
                .get(&value.browser_request.request_id)
                .is_some_and(|indexed| indexed == operation)
                && record(operation, value, prepared, fresh, journal).is_ok()
        });
    (indexes && records)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn record(
    operation: &str,
    value: &IndependentApproveRecordV1,
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<(), AgentError> {
    let actor = journal
        .actor_options
        .get(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    let lookup = prepared
        .actor_records
        .get(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    let begin = fresh
        .actor_records
        .get(operation)
        .and_then(|item| item.exchange.as_ref())
        .ok_or(AgentError::AuthorityRollback)?;
    let digest = management_command_digest(&value.browser_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let ManagementCommandV2::ApproveRevocation {
        operation_id,
        expected_state_revision,
        attempt_id,
        assertion,
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let resume =
        crate::independent_approve_state_validation_progress::resume(actor, lookup, begin, value)?;
    let projection = &resume.actor_projection;
    let ManagementProjectionBodyV2::Operation {
        operation: projected,
    } = &projection.body
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let begun = lookup
        .response
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let begin_pin = lookup
        .revocation_response_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let base = value.operation_id == operation
        && operation_id == operation
        && actor.phase == ActorOptionsPhaseV1::Complete
        && matches!(
            actor.browser_request.command,
            ManagementCommandV2::ApprovalOptions { .. }
        )
        && projected.operation_id == operation
        && projected.state == ManagementOperationState::AwaitingApprovalUv
        && projected.state_revision == *expected_state_revision
        && options.attempt_id == *attempt_id
        && options.credential_id == assertion.credential_id
        && value.browser_request_digest_sha256 == digest
        && value.response_key_id == begun.response.key_id
        && value.response_minimum_generation == begun.response.config_generation
        && value.response_key_id == begin_pin.key_id
        && value.response_public_key_hex == begin_pin.public_key_hex
        && value.response_minimum_generation == begin_pin.minimum_config_generation
        && crate::independent_approve_trust::current(value, begun).is_ok()
        && value.expires_at_epoch_s
            == crate::independent_approve_state_expiration::expiration(&resume)?
        && crate::independent_approve_state_validation_progress::observed(
            value.current_observed_at_epoch_s,
            value.current_exchange.as_ref(),
            value.updated_at_epoch_s,
        )
        && crate::independent_approve_state_validation_progress::observed(
            value.reservation_current_observed_at_epoch_s,
            value.reservation_current_exchange.as_ref(),
            value.updated_at_epoch_s,
        )
        && crate::independent_approve_state_validation_progress::valid(value);
    if !base || !crate::independent_approve_state_phase_validation::valid(value) {
        return Err(AgentError::AuthorityRollback);
    }
    crate::independent_approve_state_wire::exact(&resume)
}
