use crowsi_credential_authority_contracts::{
    EndpointRevocationFinalizeRequestV1, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn ready(
    state: &DurableSecurityState,
    operation: &str,
    final_exchange: &SignedAuthorityExchangeV1,
    request: &EndpointRevocationFinalizeRequestV1,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    let wire = serde_json::to_string(request).map_err(|_| AgentError::RequestInvalid)?;
    if wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::RequestInvalid);
    }
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .source_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != SourceApprovePhaseV1::RevocationFinalUnknown {
            let same = matches!(
                record.phase,
                SourceApprovePhaseV1::FinalizePrepared
                    | SourceApprovePhaseV1::FinalizeInvoking
                    | SourceApprovePhaseV1::FinalizeUnknown
                    | SourceApprovePhaseV1::Complete
            ) && record.revocation_final_exchange.as_ref() == Some(final_exchange)
                && record.revocation_finalize_request.as_ref() == Some(request)
                && record.revocation_finalize_request_json.as_deref() == Some(&wire);
            if same {
                return unchanged(operation, &prepared, &fresh, &journal);
            }
            return Err(AgentError::OperationReplay);
        }
        if record.revocation_final_request.as_ref() != Some(&final_exchange.request)
            || record.revocation_finalize_request_id.as_deref() != Some(&request.request_id)
        {
            return Err(AgentError::AuthorityResponseInvalid);
        }
        record.revocation_final_exchange = Some(final_exchange.clone());
        record.revocation_finalize_request = Some(request.clone());
        record.revocation_finalize_request_json = Some(wire);
        record.phase = SourceApprovePhaseV1::FinalizePrepared;
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
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
