use crowsi_credential_authority_contracts::ManagementRequestV2;
use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{
    AgentError,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    source_options_state_types::OperationJournalV1,
};

pub(crate) fn resume(
    key: &str,
    journal: &OperationJournalV1,
) -> Result<ReconcileRecordV1, AgentError> {
    journal
        .reconciliations
        .get(key)
        .map(|value| value.as_ref().clone())
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn exact_retry(
    value: &ReconcileRecordV1,
    browser: &ManagementRequestV2,
    digest: &str,
) -> bool {
    value.browser_request == *browser && value.browser_request_digest_sha256 == digest
}

pub(super) fn expiration(value: &ReconcileRecordV1) -> Result<u64, AgentError> {
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
    Ok(expires)
}

pub(super) fn central_ambiguous(value: &ReconcileRecordV1) -> bool {
    matches!(
        value.phase,
        ReconcilePhaseV1::CentralInvoking | ReconcilePhaseV1::Unknown
    )
}
