use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelFinalizeRequestV1, SignedAuthorityExchangeV1,
};

use crate::{
    AgentError,
    cancel_state_types::{CancelPhaseV1, CancelRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(super) fn persist(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    finalize: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    if serde_json::to_vec(finalize)
        .map_err(|_| AgentError::RequestInvalid)?
        .len()
        > source_options_state::MAXIMUM_PHASE_WIRE_BYTES
    {
        return Err(AgentError::RequestInvalid);
    }
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let before = crate::cancel_state_capacity::checkpoint(record)?;
        if record.phase != CancelPhaseV1::CancelPendingUnknown
            || finalize.cancel_pending_exchange != *exchange
        {
            return Err(AgentError::OperationReplay);
        }
        record.cancel_finalize_request = Some(finalize.clone());
        record.execution_cancel_request = None;
        record.execution_cancellation = None;
        record.phase = CancelPhaseV1::CancelFinalizePrepared;
        record.expires_at_epoch_s = crate::cancel_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        crate::cancel_state_capacity::rebalance(record, before)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
