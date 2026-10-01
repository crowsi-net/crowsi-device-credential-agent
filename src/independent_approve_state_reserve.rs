use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementRequestV2, management_command_digest,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    independent_approve_state_types::IndependentApproveResume, replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn reserve(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    finish: &AuthorityRequestV1,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let (operation, revision, attempt, credential) = command(browser)?;
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        if let Some(existing) = journal.independent_approval_index.get(&browser.request_id) {
            let value =
                crate::independent_approve_state::resume(existing, &prepared, &fresh, &journal)?;
            if crate::independent_approve_state::exact_retry(&value.approval, browser, &digest) {
                return Ok((value, false));
            }
            return Err(AgentError::OperationReplay);
        }
        if crate::source_options_state_indexes::request_exists(&journal, &browser.request_id)
            || journal.independent_approvals.len()
                >= crate::source_options_state::MAXIMUM_SOURCE_OPERATIONS
        {
            return Err(AgentError::OperationReplay);
        }
        let record = crate::independent_approve_state_reserve_record::selected(
            operation, revision, attempt, credential, browser, digest, finish, now, &prepared,
            &fresh, &journal,
        )?;
        journal
            .independent_approval_index
            .insert(browser.request_id.clone(), operation.into());
        journal
            .independent_approvals
            .insert(operation.into(), Box::new(record));
        let shell =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        let expires = crate::independent_approve_state_expiration::expiration(&shell)?;
        if now >= expires {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        journal
            .independent_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?
            .expires_at_epoch_s = expires;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn command(value: &ManagementRequestV2) -> Result<(&str, u64, &str, &str), AgentError> {
    let ManagementCommandV2::ApproveRevocation {
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
