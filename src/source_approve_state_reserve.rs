use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementRequestV2, management_command_digest,
};
use ihat_identity_assertion_contracts::{AuthorityRequestV1, AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::SourceApproveResume,
    source_options_state::{self, SourceOptionsPhaseV1},
};

pub(crate) fn reserve(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    finish_request: &AuthorityRequestV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let ManagementCommandV2::SourceApprove {
        operation_id,
        expected_state_revision,
        attempt_id,
        assertion,
    } = &browser.command
    else {
        return Err(AgentError::RequestInvalid);
    };
    if *expected_state_revision != 1 {
        return Err(AgentError::RequestInvalid);
    }
    let digest = management_command_digest(browser).map_err(|_| AgentError::RequestInvalid)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        if let Some(operation) = journal.source_approval_index.get(&browser.request_id) {
            let value =
                crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
            if crate::source_approve_state::exact_retry(&value.approval, browser, &digest) {
                return Ok((value, false));
            }
            return Err(AgentError::OperationReplay);
        }
        if journal.source_approvals.contains_key(operation_id)
            || journal
                .records
                .get(operation_id)
                .is_none_or(|value| value.phase != SourceOptionsPhaseV1::Complete)
        {
            return Err(AgentError::OperationReplay);
        }
        let selected = fresh
            .records
            .get(operation_id)
            .and_then(|value| value.exchange.as_ref())
            .ok_or(AgentError::AuthorityRollback)?;
        let ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options),
        } = &selected.response.outcome
        else {
            return Err(AgentError::AuthorityRollback);
        };
        if options.attempt_id != *attempt_id || options.credential_id != assertion.credential_id {
            return Err(AgentError::RequestInvalid);
        }
        let expires = crate::source_approve_state::selected_expiration(selected)?;
        if now >= expires {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        journal
            .source_approval_index
            .insert(browser.request_id.clone(), operation_id.clone());
        journal.source_approvals.insert(
            operation_id.clone(),
            Box::new(crate::source_approve_state_reserve_record::initial(
                operation_id,
                browser,
                digest,
                finish_request,
                expires,
                now,
            )),
        );
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result =
            crate::source_approve_state::resume(operation_id, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
