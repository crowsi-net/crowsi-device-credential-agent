use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn finish_complete(
    state: &DurableSecurityState,
    operation: &str,
    finish: &SignedAuthorityExchangeV1,
    current_request: &AuthorityRequestV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let selected = fresh
            .records
            .get(operation)
            .and_then(|value| value.exchange.as_ref())
            .ok_or(AgentError::AuthorityRollback)?;
        let record = journal
            .source_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != SourceApprovePhaseV1::FinishPrepared {
            let winner = record.phase == SourceApprovePhaseV1::CurrentPrepared
                && record.finish_exchange.as_ref() == Some(finish)
                && record.current_request.is_some();
            if winner {
                let result =
                    crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
                return Ok((result, false));
            }
            return Err(AgentError::OperationReplay);
        }
        if finish.request != record.finish_request {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.finish_exchange = Some(finish.clone());
        record.current_request = Some(current_request.clone());
        record.phase = SourceApprovePhaseV1::CurrentPrepared;
        record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
        record.updated_at_epoch_s = now;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn current_complete(
    state: &DurableSecurityState,
    operation: &str,
    current: &SignedAuthorityExchangeV1,
    envelope: &EndpointManagementEnvelopeV2,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let wire = serde_json::to_string(envelope).map_err(|_| AgentError::RequestInvalid)?;
    if wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::RequestInvalid);
    }
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let selected = fresh
            .records
            .get(operation)
            .and_then(|value| value.exchange.as_ref())
            .ok_or(AgentError::AuthorityRollback)?;
        let record = journal
            .source_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != SourceApprovePhaseV1::CurrentObserveUnknown {
            let same = record.phase == SourceApprovePhaseV1::CentralPrepared
                && record.current_exchange.as_ref() == Some(current)
                && record.central_envelope.as_ref() == Some(envelope)
                && record.central_envelope_json.as_deref() == Some(&wire);
            if same {
                let result =
                    crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
                return Ok((result, false));
            }
            return Err(AgentError::OperationReplay);
        }
        if record.current_request.as_ref() != Some(&current.request) {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_observed_at_epoch_s = Some(now);
        record.central_envelope_json = Some(wire);
        record.central_envelope = Some(envelope.clone());
        record.phase = SourceApprovePhaseV1::CentralPrepared;
        record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
        record.updated_at_epoch_s = now;
        if now >= record.expires_at_epoch_s {
            return Err(AgentError::FreshUserVerificationRequired);
        }
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
