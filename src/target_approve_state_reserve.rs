use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementOperationState, ManagementProjectionBodyV2, ManagementRequestV2,
    management_command_digest,
};
use ihat_identity_assertion_contracts::{AuthorityRequestV1, AuthorityResult, ResponseOutcome};

use crate::{
    AgentError, actor_options_state_types::ActorOptionsPhaseV1, replay::DurableSecurityState,
    source_options_state, target_approve_state_types::TargetApproveResume,
};

pub(crate) fn reserve(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    finish: &AuthorityRequestV1,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let (operation, revision, attempt, credential) =
        crate::target_approve_state_reserve_values::command(browser)?;
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        if let Some(existing) = journal.target_approval_index.get(&browser.request_id) {
            let value = crate::target_approve_state::resume(existing, &prepared, &fresh, &journal)?;
            if crate::target_approve_state::exact_retry(&value.approval, browser, &digest) {
                return Ok((value, false));
            }
            return Err(AgentError::OperationReplay);
        }
        let actor = journal
            .actor_options
            .get(operation)
            .ok_or(AgentError::OperationReplay)?;
        if journal.target_approvals.contains_key(operation)
            || actor.phase != ActorOptionsPhaseV1::Complete
            || !matches!(
                actor.browser_request.command,
                ManagementCommandV2::TargetOptions { .. }
            )
        {
            return Err(AgentError::OperationReplay);
        }
        if now < actor.updated_at_epoch_s {
            return Err(AgentError::AuthorityRollback);
        }
        let projection = actor
            .response
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let ManagementProjectionBodyV2::Operation {
            operation: selected,
        } = &projection.body
        else {
            return Err(AgentError::AuthorityRollback);
        };
        if selected.operation_id != operation
            || selected.state_revision != revision
            || selected.state != ManagementOperationState::AwaitingTargetUv
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
        let mut record = crate::target_approve_state_reserve_values::initial(
            operation, browser, digest, finish, now,
        );
        let shell = crate::target_approve_state_reserve_values::resume_shell(
            &prepared,
            &fresh,
            &journal,
            record.clone(),
            operation,
        )?;
        record.expires_at_epoch_s = crate::target_approve_state::selected_expiration(&shell)?;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        journal
            .target_approval_index
            .insert(browser.request_id.clone(), operation.into());
        journal
            .target_approvals
            .insert(operation.into(), Box::new(record));
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
