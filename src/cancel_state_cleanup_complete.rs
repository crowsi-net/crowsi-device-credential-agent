use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancellationCleanupCompleteV1,
    verify_endpoint_revocation_execution_cancellation_cleanup_complete_historic,
};

use crate::{
    AgentError,
    cancel_state_types::{CancelCentralTrustPinV1, CancelPhaseV1, CancelRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(super) fn accepted(
    state: &DurableSecurityState,
    operation: &str,
    wire: &[u8],
    response: &EndpointRevocationExecutionCancellationCleanupCompleteV1,
    pin: CancelCentralTrustPinV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    bounded(wire)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let before = crate::cancel_state_capacity::checkpoint(record)?;
        if record.phase != CancelPhaseV1::CleanupCompleteUnknown {
            return Err(AgentError::OperationReplay);
        }
        let request = record
            .cleanup_complete_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let acknowledge = record
            .cleanup_response_trust
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        verify_endpoint_revocation_execution_cancellation_cleanup_complete_historic(
            response,
            request,
            &request.cleanup,
            &pin.peer_device_ref,
            &crate::cancel_cleanup_complete_trust::historic(&pin, acknowledge),
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        record.cleanup_complete_response = Some(response.clone());
        record.cleanup_complete_trust = Some(pin);
        record.phase = CancelPhaseV1::CleanupCompleteAccepted;
        record.updated_at_epoch_s = now;
        crate::cancel_state_capacity::rebalance(record, before)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

pub(super) fn complete(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
) -> Result<(), AgentError> {
    state.transaction_namespaces(|values| {
        let (mut prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase != CancelPhaseV1::CleanupCompleteAccepted {
            return Err(AgentError::OperationReplay);
        }
        record.updated_at_epoch_s = now;
        crate::cancel_state_cleanup::terminal(
            operation,
            &mut prepared,
            &mut fresh,
            &mut journal,
            now,
        )?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok(((), true))
    })
}

fn bounded(wire: &[u8]) -> Result<(), AgentError> {
    if wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    std::str::from_utf8(wire)
        .map(|_| ())
        .map_err(|_| AgentError::ResponseInvalid)
}
