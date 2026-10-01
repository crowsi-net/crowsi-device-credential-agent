use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, RevocationSourceCeremonyV1,
};
use ihat_identity_assertion_contracts::{AuthorityEvidence, AuthorityResult, ResponseOutcome};

use crate::AgentError;
use crate::source_approve_state_types::{SourceApprovePhaseV1 as Phase, SourceApproveRecordV1};

pub(crate) fn expiration(
    value: &SourceApproveRecordV1,
    expires: &mut u64,
) -> Result<(), AgentError> {
    if let Some(request) = &value.revocation_begin_request {
        for evidence in &request.evidence {
            let expiry = match evidence {
                AuthorityEvidence::FreshUv(item) => item.expires_at_epoch_s,
                AuthorityEvidence::Signed(item) => item.expires_at_epoch_s,
            };
            *expires = (*expires).min(expiry);
        }
    }
    if let Some(exchange) = &value.revocation_begin_exchange {
        let ResponseOutcome::Committed {
            result: AuthorityResult::RevocationBegun(metadata),
        } = &exchange.response.outcome
        else {
            return Err(AgentError::AuthorityRollback);
        };
        *expires = (*expires)
            .min(exchange.response.expires_at_epoch_s)
            .min(metadata.expires_at_epoch_s);
    }
    Ok(())
}

pub(crate) fn validate(
    value: &SourceApproveRecordV1,
    prepared: &EndpointPreparedOperationV2,
) -> Result<(), AgentError> {
    if none(value) {
        let before_revocation = matches!(
            value.phase,
            Phase::FinishPrepared
                | Phase::CurrentPrepared
                | Phase::CurrentInvoking
                | Phase::CurrentUnknown
                | Phase::CurrentObservePrepared
                | Phase::CurrentObserveInvoking
                | Phase::CurrentObserveUnknown
        );
        return (matches!(prepared.intent, ManagementIntentV2::DeviceTransfer { .. })
            || before_revocation)
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    }
    if matches!(prepared.intent, ManagementIntentV2::DeviceTransfer { .. }) {
        return Err(AgentError::AuthorityRollback);
    }
    let request = value
        .revocation_begin_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let finish = value
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let fresh = crowsi_credential_authority_contracts::fresh_uv_from_finish_exchange(
        finish,
        &value.browser_request.command,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    let historic = crate::source_approve_state_finalization::historic(value);
    if !historic {
        crate::source_approve_revocation_request::validate_begin(
            prepared,
            fresh,
            request,
            value.updated_at_epoch_s,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
    }
    if let Some(exchange) = &value.revocation_begin_exchange {
        crate::source_approve_state_revocation_trust::validate(value, exchange)?;
        crate::source_approve_state_revocation_final::exact_request(request, exchange)?;
        if historic {
            crate::source_approve_revocation_response_begin::metadata(prepared, exchange)
                .map_err(|_| AgentError::AuthorityRollback)?;
        } else {
            crate::source_approve_revocation_response_begin::current(
                prepared,
                exchange,
                value.updated_at_epoch_s,
            )
            .map_err(|_| AgentError::AuthorityRollback)?;
        }
        crate::source_approve_state_revocation_final::validate(value, prepared, exchange)?;
    } else if value.revocation_final_request.is_some() || value.revocation_final_exchange.is_some()
    {
        return Err(AgentError::AuthorityRollback);
    }
    Ok(())
}

pub(crate) fn none(value: &SourceApproveRecordV1) -> bool {
    value.revocation_begin_request.is_none()
        && value.revocation_begin_exchange.is_none()
        && crate::source_approve_state_revocation_trust::empty(value)
        && value.revocation_final_request.is_none()
        && value.revocation_final_exchange.is_none()
}

pub(crate) fn begun(value: &SourceApproveRecordV1) -> bool {
    value.revocation_begin_request.is_some()
        && value.revocation_begin_exchange.is_some()
        && value.revocation_final_request.is_none()
        && value.revocation_final_exchange.is_none()
}

pub(crate) fn awaiting_final(value: &SourceApproveRecordV1) -> bool {
    value.revocation_begin_request.is_some()
        && value.revocation_begin_exchange.is_some()
        && value.revocation_final_request.is_some()
        && value.revocation_final_exchange.is_none()
}

pub(crate) fn finalized(value: &SourceApproveRecordV1) -> bool {
    value.revocation_begin_request.is_some()
        && value.revocation_begin_exchange.is_some()
        && value.revocation_final_request.is_some()
        && value.revocation_final_exchange.is_some()
}

pub(crate) fn ceremony(value: &SourceApproveRecordV1) -> Option<RevocationSourceCeremonyV1> {
    value
        .revocation_begin_exchange
        .as_ref()
        .map(|begin| RevocationSourceCeremonyV1 {
            begin: begin.clone(),
            final_revoke: None,
        })
}
