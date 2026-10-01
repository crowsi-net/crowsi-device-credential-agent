use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointManagementEnvelopeV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn current_ready(
    state: &DurableSecurityState,
    operation: &str,
    current: &SignedAuthorityExchangeV1,
    begin: &AuthorityRequestV1,
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
        if record.phase != SourceApprovePhaseV1::CurrentObserveUnknown {
            let same = record.phase == SourceApprovePhaseV1::RevocationBeginPrepared
                && record.current_exchange.as_ref() == Some(current)
                && record.revocation_begin_request.as_ref() == Some(begin);
            if same {
                return unchanged(operation, &prepared, &fresh, &journal);
            }
            return Err(AgentError::OperationReplay);
        }
        if record.current_request.as_ref() != Some(&current.request) {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.current_observed_at_epoch_s = Some(now);
        record.revocation_begin_request = Some(begin.clone());
        record.phase = SourceApprovePhaseV1::RevocationBeginPrepared;
        update(selected, record, now)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(crate) fn begun_ready(
    state: &DurableSecurityState,
    operation: &str,
    begun: &SignedAuthorityExchangeV1,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    final_request: Option<&AuthorityRequestV1>,
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
        if record.phase != SourceApprovePhaseV1::RevocationBeginPrepared {
            let same = record.phase == SourceApprovePhaseV1::CentralPrepared
                && record.revocation_begin_exchange.as_ref() == Some(begun)
                && record.revocation_final_request.as_ref() == final_request
                && record.central_envelope.as_ref() == Some(envelope)
                && record.central_envelope_json.as_deref() == Some(&wire);
            if same {
                return unchanged(operation, &prepared, &fresh, &journal);
            }
            return Err(AgentError::OperationReplay);
        }
        if record.revocation_begin_request.as_ref() != Some(&begun.request) {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.revocation_begin_exchange = Some(begun.clone());
        crate::source_approve_state_revocation_trust::set(record, begun, trust)?;
        record.revocation_final_request = final_request.cloned();
        record.central_envelope = Some(envelope.clone());
        record.central_envelope_json = Some(wire);
        record.phase = SourceApprovePhaseV1::CentralPrepared;
        update(selected, record, now)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn update(
    selected: &SignedAuthorityExchangeV1,
    record: &mut crate::source_approve_state_types::SourceApproveRecordV1,
    now: u64,
) -> Result<(), AgentError> {
    record.expires_at_epoch_s = crate::source_approve_state::expiration(selected, record)?;
    record.updated_at_epoch_s = now;
    (now < record.expires_at_epoch_s)
        .then_some(())
        .ok_or(AgentError::FreshUserVerificationRequired)
}

fn unchanged(
    operation: &str,
    prepared: &crate::source_options_state_types::PreparedOperationsV1,
    fresh: &crate::source_options_state_types::FreshUvAttemptsV1,
    journal: &crate::source_options_state_types::OperationJournalV1,
) -> Result<(SourceApproveResume, bool), AgentError> {
    Ok((
        crate::source_approve_state::resume(operation, prepared, fresh, journal)?,
        false,
    ))
}
