use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementOperationState, ManagementProjectionBodyV2,
    management_command_digest,
};
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    actor_options_state_types::ActorOptionsPhaseV1,
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
    target_approve_state_types::{TargetApproveRecordV1, TargetApproveResume},
};

pub(super) fn all(
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
) -> Result<(), AgentError> {
    let indexes = journal
        .target_approval_index
        .iter()
        .all(|(request, operation)| {
            journal
                .target_approvals
                .get(operation)
                .is_some_and(|value| {
                    value.browser_request.request_id == *request && value.operation_id == *operation
                })
        });
    let records = journal.target_approvals.iter().all(|(operation, value)| {
        journal
            .target_approval_index
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
    value: &TargetApproveRecordV1,
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
    let ManagementCommandV2::TargetApprove {
        operation_id,
        expected_state_revision,
        attempt_id,
        assertion,
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let projection = actor
        .response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
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
    let resume = TargetApproveResume {
        selected_identity: actor
            .current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        selected_begin: begin.clone(),
        lookup: lookup.clone(),
        actor_projection: projection.clone(),
        approval: Box::new(value.clone()),
    };
    let base = value.operation_id == operation
        && operation_id == operation
        && actor.phase == ActorOptionsPhaseV1::Complete
        && matches!(
            actor.browser_request.command,
            ManagementCommandV2::TargetOptions { .. }
        )
        && projected.operation_id == operation
        && projected.state == ManagementOperationState::AwaitingTargetUv
        && projected.state_revision == *expected_state_revision
        && options.attempt_id == *attempt_id
        && options.credential_id == assertion.credential_id
        && value.browser_request_digest_sha256 == digest
        && value.expires_at_epoch_s == crate::target_approve_state_expiration::expiration(&resume)?
        && value.current_observed_at_epoch_s.is_none_or(|observed| {
            value.current_exchange.as_ref().is_some_and(|current| {
                current.response.issued_at_epoch_s <= observed
                    && observed <= value.updated_at_epoch_s
                    && observed < value.expires_at_epoch_s
            })
        })
        && (value.updated_at_epoch_s <= value.expires_at_epoch_s
            || crate::target_approve_state::can_resume_expired(value));
    if !base
        || !crate::target_approve_state_finish_validation::valid(value)?
        || !crate::target_approve_state_phase_validation::valid(value)
    {
        return Err(AgentError::AuthorityRollback);
    }
    crate::target_approve_state_wire::exact(&resume)
}
