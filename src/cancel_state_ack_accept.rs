use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelCleanupCompleteRequestV1, SignedAuthorityExchangeV1,
    validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance,
};

use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1, CancelRecordV1, CancelResponseTrustPinV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(super) fn persist(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    request: &EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    pin: CancelResponseTrustPinV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let before = crate::cancel_state_capacity::checkpoint(record)?;
        if record.phase != CancelPhaseV1::CleanupAckUnknown
            || request.acknowledge_exchange != *exchange
            || record.cancel_finalize_request.as_ref() != Some(&request.cancel_finalize_request)
            || record.cancellation_cleanup.as_ref() != Some(&request.cleanup)
        {
            return Err(AgentError::OperationReplay);
        }
        validate_endpoint_revocation_execution_cancel_cleanup_complete_against_acceptance(
            request,
            &request.cleanup,
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        record.cleanup_complete_request = Some(request.clone());
        record.cleanup_response_trust = Some(pin);
        record.cancel_finalize_request = None;
        record.cancellation_cleanup = None;
        record.phase = CancelPhaseV1::CleanupCompletePrepared;
        record.expires_at_epoch_s = crate::cancel_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        crate::cancel_state_capacity::rebalance(record, before)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
