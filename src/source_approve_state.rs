use crowsi_credential_authority_contracts::ManagementRequestV2;
use ihat_identity_assertion_contracts::{AuthorityResult, ResponseOutcome};

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApproveRecordV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn load(
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
) -> Result<Option<SourceApproveResume>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, journal) = source_options_state::documents(values)?;
        let Some(operation) = journal.source_approval_index.get(&browser.request_id) else {
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
    prepared: &crate::source_options_state_types::PreparedOperationsV1,
    fresh: &crate::source_options_state_types::FreshUvAttemptsV1,
    journal: &crate::source_options_state_types::OperationJournalV1,
) -> Result<SourceApproveResume, AgentError> {
    Ok(SourceApproveResume {
        source: prepared
            .records
            .get(operation)
            .cloned()
            .ok_or(AgentError::AuthorityRollback)?,
        selected_begin: fresh
            .records
            .get(operation)
            .and_then(|value| value.exchange.clone())
            .ok_or(AgentError::AuthorityRollback)?,
        source_projection: journal
            .records
            .get(operation)
            .and_then(|value| value.response.clone())
            .ok_or(AgentError::AuthorityRollback)?,
        approval: journal
            .source_approvals
            .get(operation)
            .cloned()
            .ok_or(AgentError::AuthorityRollback)?,
    })
}

pub(super) fn selected_expiration(
    selected: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Result<u64, AgentError> {
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &selected.response.outcome
    else {
        return Err(AgentError::AuthorityRollback);
    };
    Ok(options.expires_at_epoch_s)
}

pub(super) fn expiration(
    selected: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    value: &SourceApproveRecordV1,
) -> Result<u64, AgentError> {
    if crate::source_approve_state_reservation_expiration::applies(value.phase)
        && value.reservation_current_request.is_some()
    {
        return crate::source_approve_state_reservation_expiration::expiration(value);
    }
    let mut expires = selected_expiration(selected)?;
    if let Some(finish) = &value.finish_exchange {
        let fresh = crowsi_credential_authority_contracts::fresh_uv_from_finish_exchange(
            finish,
            &value.browser_request.command,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(finish.response.expires_at_epoch_s)
            .min(fresh.expires_at_epoch_s);
    }
    if let Some(request) = &value.current_request {
        for evidence in &request.evidence {
            let ihat_identity_assertion_contracts::AuthorityEvidence::Signed(proof) = evidence
            else {
                return Err(AgentError::AuthorityRollback);
            };
            expires = expires.min(proof.expires_at_epoch_s);
        }
    }
    if let Some(current) = &value.current_exchange {
        let identity =
            crowsi_credential_authority_contracts::identity_evidence_from_exchange(current)
                .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(current.response.expires_at_epoch_s)
            .min(identity.assertion.expires_at_epoch_s)
            .min(identity.current_status.expires_at_epoch_s);
    }
    crate::source_approve_state_revocation::expiration(value, &mut expires)?;
    Ok(expires)
}

pub(super) fn exact_retry(
    value: &SourceApproveRecordV1,
    browser: &ManagementRequestV2,
    digest: &str,
) -> bool {
    value.browser_request == *browser && value.browser_request_digest_sha256 == digest
}
