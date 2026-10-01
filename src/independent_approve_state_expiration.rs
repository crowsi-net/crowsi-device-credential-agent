use ihat_identity_assertion_contracts::AuthorityEvidence;

use crate::{
    AgentError,
    independent_approve_state_types::{IndependentApprovePhaseV1 as P, IndependentApproveResume},
};

pub(super) fn expiration(value: &IndependentApproveResume) -> Result<u64, AgentError> {
    let phase = value.approval.phase;
    if matches!(
        phase,
        P::ApprovalInvoking
            | P::ApprovalUnknown
            | P::PreFinalInvoking
            | P::PreFinalUnknown
            | P::PreFinalAccepted
            | P::ReservationCurrentInvoking
            | P::ReservationCurrentUnknown
    ) {
        return begin(value);
    }
    if matches!(
        phase,
        P::ReservationCurrentPrepared
            | P::ReservationCurrentObservePrepared
            | P::ReservationCurrentObserveInvoking
            | P::ReservationCurrentObserveUnknown
            | P::ExecutionReservePrepared
            | P::ExecutionReserveInvoking
            | P::ExecutionReserveUnknown
            | P::FinalPrepared
            | P::FinalInvoking
            | P::FinalUnknown
            | P::FinalAccepted
            | P::FinalizePrepared
            | P::FinalizeInvoking
            | P::FinalizeUnknown
            | P::Complete
    ) {
        return reservation(value);
    }
    approval(value)
}

fn approval(value: &IndependentApproveResume) -> Result<u64, AgentError> {
    let mut expires = crate::independent_approve_state::selected_expiration(value)?;
    let record = &value.approval;
    if let Some(finish) = &record.finish_exchange {
        let fresh = crowsi_credential_authority_contracts::fresh_uv_from_finish_exchange(
            finish,
            &record.browser_request.command,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        expires = expires
            .min(finish.response.expires_at_epoch_s)
            .min(fresh.expires_at_epoch_s);
    }
    if record.current_exchange.is_none() {
        expires = request_expiration(record.current_request.as_ref(), expires)?;
    }
    if let Some(current) = &record.current_exchange {
        expires = expires.min(identity_expiration(current)?);
    }
    if record.approval_exchange.is_none() {
        expires = request_expiration(record.approval_request.as_ref(), expires)?;
    } else if matches!(record.phase, P::ApprovalAccepted | P::PreFinalPrepared) {
        expires = expires.min(
            record
                .approval_exchange
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?
                .response
                .expires_at_epoch_s,
        );
    }
    Ok(expires)
}

fn reservation(value: &IndependentApproveResume) -> Result<u64, AgentError> {
    let mut expires = begin(value)?;
    let record = &value.approval;
    if record.reservation_current_exchange.is_none() {
        expires = request_expiration(record.reservation_current_request.as_ref(), expires)?;
    }
    if let Some(current) = &record.reservation_current_exchange {
        expires = expires.min(identity_expiration(current)?);
    }
    Ok(expires)
}

fn begin(value: &IndependentApproveResume) -> Result<u64, AgentError> {
    let begun = crate::independent_approve_ceremony_context::begun(value)?;
    Ok(crate::source_approve_revocation_response_begin::metadata(
        &value.lookup.response.prepared,
        begun,
    )?
    .expires_at_epoch_s)
}

fn request_expiration(
    request: Option<&ihat_identity_assertion_contracts::AuthorityRequestV1>,
    mut expires: u64,
) -> Result<u64, AgentError> {
    if let Some(request) = request {
        for proof in &request.evidence {
            let AuthorityEvidence::Signed(proof) = proof else {
                return Err(AgentError::AuthorityRollback);
            };
            expires = expires.min(proof.expires_at_epoch_s);
        }
    }
    Ok(expires)
}

fn identity_expiration(
    value: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
) -> Result<u64, AgentError> {
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(value)
        .map_err(|_| AgentError::AuthorityRollback)?;
    Ok(value
        .response
        .expires_at_epoch_s
        .min(identity.assertion.expires_at_epoch_s)
        .min(identity.current_status.expires_at_epoch_s))
}
