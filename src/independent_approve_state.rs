use crowsi_credential_authority_contracts::ManagementRequestV2;
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    independent_approve_state_types::{
        IndependentApprovePhaseV1, IndependentApproveRecordV1, IndependentApproveResume,
    },
    source_options_state_types::{FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1},
};

pub(super) const fn phase_can_resume_expired(value: IndependentApprovePhaseV1) -> bool {
    matches!(
        value,
        IndependentApprovePhaseV1::ExecutionReserveInvoking
            | IndependentApprovePhaseV1::ExecutionReserveUnknown
            | IndependentApprovePhaseV1::FinalPrepared
            | IndependentApprovePhaseV1::FinalInvoking
            | IndependentApprovePhaseV1::FinalUnknown
            | IndependentApprovePhaseV1::FinalAccepted
            | IndependentApprovePhaseV1::FinalizePrepared
            | IndependentApprovePhaseV1::FinalizeInvoking
            | IndependentApprovePhaseV1::FinalizeUnknown
            | IndependentApprovePhaseV1::Complete
    )
}

pub(crate) fn load(
    state: &crate::replay::DurableSecurityState,
    browser: &ManagementRequestV2,
) -> Result<Option<IndependentApproveResume>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, journal) = crate::source_options_state::documents(values)?;
        let Some(operation) = journal.independent_approval_index.get(&browser.request_id) else {
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
) -> Result<IndependentApproveResume, AgentError> {
    let actor = journal
        .actor_options
        .get(operation)
        .ok_or(AgentError::AuthorityRollback)?;
    Ok(IndependentApproveResume {
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
            .independent_approvals
            .get(operation)
            .cloned()
            .ok_or(AgentError::AuthorityRollback)?,
    })
}

pub(super) fn selected_expiration(value: &IndependentApproveResume) -> Result<u64, AgentError> {
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
    let begun = value
        .lookup
        .response
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let ceremony = crate::source_approve_revocation_response_begin::metadata(
        &value.lookup.response.prepared,
        begun,
    )?;
    Ok(value
        .lookup
        .response
        .prepared
        .expires_at_epoch_s
        .min(operation.expires_at_epoch_s)
        .min(options.expires_at_epoch_s)
        .min(ceremony.expires_at_epoch_s))
}

pub(super) fn exact_retry(
    value: &IndependentApproveRecordV1,
    browser: &ManagementRequestV2,
    digest: &str,
) -> bool {
    value.browser_request == *browser && value.browser_request_digest_sha256 == digest
}

#[cfg(test)]
mod tests {
    use super::{IndependentApprovePhaseV1 as P, phase_can_resume_expired};

    #[test]
    fn reservation_allows_first_and_ambiguous_final_after_expiry() {
        for phase in [P::FinalPrepared, P::FinalInvoking, P::FinalUnknown] {
            assert!(phase_can_resume_expired(phase));
        }
    }

    #[test]
    fn ambiguous_reserve_recovers_but_uninvoked_reserve_does_not() {
        assert!(!phase_can_resume_expired(P::ExecutionReservePrepared));
        assert!(phase_can_resume_expired(P::ExecutionReserveInvoking));
        assert!(phase_can_resume_expired(P::ExecutionReserveUnknown));
        assert!(!phase_can_resume_expired(P::PreFinalAccepted));
    }
}
