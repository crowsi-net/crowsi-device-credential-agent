use crowsi_credential_authority_contracts::ManagementRequestV2;
use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1, CancelRecordV1},
    source_options_state_types::OperationJournalV1,
};

pub(crate) fn resume(
    operation: &str,
    journal: &OperationJournalV1,
) -> Result<Box<CancelRecordV1>, AgentError> {
    journal
        .cancellations
        .get(operation)
        .cloned()
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn exact_retry(
    value: &CancelRecordV1,
    browser: &ManagementRequestV2,
    digest: &str,
) -> bool {
    value.browser_request == *browser && value.browser_request_digest_sha256 == digest
}

pub(super) fn expiration(value: &CancelRecordV1) -> Result<u64, AgentError> {
    let [AuthorityEvidence::Signed(sender)] = value.current_request.evidence.as_slice() else {
        return Err(AgentError::AuthorityRollback);
    };
    let mut expires = sender.expires_at_epoch_s;
    if let Some(exchange) = &value.current_exchange {
        let identity =
            crowsi_credential_authority_contracts::identity_evidence_from_exchange(exchange)
                .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(exchange.response.expires_at_epoch_s)
            .min(identity.assertion.expires_at_epoch_s)
            .min(identity.current_status.expires_at_epoch_s);
    }
    if let Some(lookup) = &value.lookup_response {
        expires = expires.min(lookup.expires_at_epoch_s);
    }
    if let Some(response) = crate::cancel_state_wire::response_value(value)? {
        expires = response.expires_at_epoch_s;
    }
    Ok(expires)
}

pub(super) fn can_resume_expired(value: &CancelRecordV1) -> bool {
    matches!(
        value.phase,
        CancelPhaseV1::CentralInvoking
            | CancelPhaseV1::Unknown
            | CancelPhaseV1::ExecutionCancelPrepared
            | CancelPhaseV1::ExecutionCancelInvoking
            | CancelPhaseV1::ExecutionCancelUnknown
            | CancelPhaseV1::CancelPendingPrepared
            | CancelPhaseV1::CancelPendingInvoking
            | CancelPhaseV1::CancelPendingUnknown
            | CancelPhaseV1::CancelFinalizePrepared
            | CancelPhaseV1::CancelFinalizeInvoking
            | CancelPhaseV1::CancelFinalizeUnknown
            | CancelPhaseV1::CleanupAckPrepared
            | CancelPhaseV1::CleanupAckInvoking
            | CancelPhaseV1::CleanupAckUnknown
            | CancelPhaseV1::CleanupCompletePrepared
            | CancelPhaseV1::CleanupCompleteInvoking
            | CancelPhaseV1::CleanupCompleteUnknown
            | CancelPhaseV1::CleanupCompleteCleanupPrepared
            | CancelPhaseV1::CleanupCompleteCleanupInvoking
            | CancelPhaseV1::CleanupCompleteCleanupUnknown
            | CancelPhaseV1::CleanupCompleteAckPrepared
            | CancelPhaseV1::CleanupCompleteAckInvoking
            | CancelPhaseV1::CleanupCompleteAckUnknown
            | CancelPhaseV1::CleanupCompleteAccepted
    ) || (value.phase == CancelPhaseV1::Complete && value.cleanup_completed_id.is_some())
}
