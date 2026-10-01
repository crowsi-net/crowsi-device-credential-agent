use crowsi_credential_authority_contracts::ManagementRequestV2;
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
    target_approve_state_types::{
        TargetApprovePhaseV1, TargetApproveRecordV1, TargetApproveResume,
    },
};

pub(super) fn can_resume_expired(value: &TargetApproveRecordV1) -> bool {
    phase_can_resume_expired(value.phase)
}

pub(super) const fn phase_can_resume_expired(value: TargetApprovePhaseV1) -> bool {
    matches!(
        value,
        TargetApprovePhaseV1::CentralInvoking
            | TargetApprovePhaseV1::Unknown
            | TargetApprovePhaseV1::Complete
    )
}

pub(crate) fn load(
    state: &crate::replay::DurableSecurityState,
    browser: &ManagementRequestV2,
) -> Result<Option<TargetApproveResume>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, journal) = crate::source_options_state::documents(values)?;
        let Some(operation) = journal.target_approval_index.get(&browser.request_id) else {
            return Ok((None, false));
        };
        let value = resume(operation, &prepared, &fresh, &journal)?;
        if value.approval.browser_request != *browser {
            return Err(AgentError::OperationReplay);
        }
        Ok((Some(value), false))
    })
}

pub(crate) fn resume(
    operation: &str,
    prepared: &PreparedOperationsV1,
    fresh: &FreshUvAttemptsV1,
    journal: &OperationJournalV1,
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
        approval: journal
            .target_approvals
            .get(operation)
            .cloned()
            .ok_or(AgentError::AuthorityRollback)?,
    })
}

pub(super) fn selected_expiration(value: &TargetApproveResume) -> Result<u64, AgentError> {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &value.selected_begin.response.outcome
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let crowsi_credential_authority_contracts::ManagementProjectionBodyV2::Operation { operation } =
        &value.actor_projection.body
    else {
        return Err(AgentError::AuthorityRollback);
    };
    Ok(historic_base(
        value.lookup.response.prepared.expires_at_epoch_s,
        operation.expires_at_epoch_s,
        options.expires_at_epoch_s,
    ))
}

pub(super) const fn historic_base(prepared: u64, operation: u64, options: u64) -> u64 {
    let expires = if prepared < operation {
        prepared
    } else {
        operation
    };
    if expires < options { expires } else { options }
}

pub(super) fn exact_retry(
    value: &TargetApproveRecordV1,
    browser: &ManagementRequestV2,
    digest: &str,
) -> bool {
    value.browser_request == *browser && value.browser_request_digest_sha256 == digest
}
