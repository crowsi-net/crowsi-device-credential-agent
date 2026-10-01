use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{
    AgentError,
    source_approve_state_types::{SourceApprovePhaseV1 as P, SourceApproveRecordV1},
};

pub(super) const fn applies(phase: P) -> bool {
    matches!(
        phase,
        P::ReservationCurrentPrepared
            | P::ReservationCurrentInvoking
            | P::ReservationCurrentUnknown
            | P::ReservationCurrentObservePrepared
            | P::ReservationCurrentObserveInvoking
            | P::ReservationCurrentObserveUnknown
            | P::ExecutionReservePrepared
            | P::ExecutionReserveInvoking
            | P::ExecutionReserveUnknown
            | P::RevocationFinalPrepared
            | P::RevocationFinalInvoking
            | P::RevocationFinalUnknown
            | P::FinalizePrepared
            | P::FinalizeInvoking
            | P::FinalizeUnknown
            | P::Complete
    )
}

pub(super) fn expiration(value: &SourceApproveRecordV1) -> Result<u64, AgentError> {
    let mut expires = crate::source_approve_state_finalization::begin_expiration(value)
        .ok_or(AgentError::AuthorityRollback)?;
    if value.reservation_current_exchange.is_none() {
        if let Some(request) = value.reservation_current_request.as_ref() {
            for evidence in &request.evidence {
                let AuthorityEvidence::Signed(proof) = evidence else {
                    return Err(AgentError::AuthorityRollback);
                };
                expires = expires.min(proof.expires_at_epoch_s);
            }
        }
    }
    if let Some(exchange) = value.reservation_current_exchange.as_ref() {
        let identity =
            crowsi_credential_authority_contracts::identity_evidence_from_exchange(exchange)
                .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(exchange.response.expires_at_epoch_s)
            .min(identity.assertion.expires_at_epoch_s)
            .min(identity.current_status.expires_at_epoch_s);
    }
    Ok(expires)
}
