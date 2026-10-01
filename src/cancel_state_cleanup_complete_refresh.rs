use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancellationCleanupV1, SignedAuthorityExchangeV1,
    decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict,
    endpoint_revocation_cancellation_acknowledgement_result_digest,
    endpoint_revocation_execution_cancel_cleanup_complete_request_digest,
};

use crate::{
    AgentError,
    cancel_state_types::{
        CancelCentralTrustPinV1, CancelPhaseV1, CancelRecordV1, CancelResponseTrustPinV1,
    },
    replay::DurableSecurityState,
};

pub(super) fn cleanup(
    state: &DurableSecurityState,
    operation: &str,
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    pin: CancelCentralTrustPinV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    update(state, operation, now, |record, before| {
        if record.phase != CancelPhaseV1::CleanupCompleteCleanupUnknown {
            return Err(AgentError::OperationReplay);
        }
        let stored = record
            .cleanup_complete_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        if stored.cleanup.cleanup_id != cleanup.cleanup_id || stored.cleanup.token != cleanup.token
        {
            return Err(AgentError::AuthorityRollback);
        }
        record.cancellation_cleanup = Some(cleanup.clone());
        record.cancellation_cleanup_trust = Some(pin);
        record.cleanup_response_trust = None;
        record.phase = CancelPhaseV1::CleanupCompleteAckPrepared;
        crate::cancel_state_capacity::rebalance(record, before)
    })
}

pub(super) fn acknowledgement(
    state: &DurableSecurityState,
    operation: &str,
    exchange: &SignedAuthorityExchangeV1,
    pin: CancelResponseTrustPinV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    update(state, operation, now, |record, before| {
        if record.phase != CancelPhaseV1::CleanupCompleteAckUnknown {
            return Err(AgentError::OperationReplay);
        }
        let stored = record
            .cleanup_complete_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let old_result = result(stored)?;
        let mut updated = stored.clone();
        updated.cleanup = Box::new(
            record
                .cancellation_cleanup
                .clone()
                .ok_or(AgentError::AuthorityRollback)?,
        );
        updated.acknowledge_exchange = exchange.clone();
        let updated = exact(&updated)?;
        stable(stored, &updated)?;
        if result(&updated)? != old_result {
            return Err(AgentError::AuthorityRollback);
        }
        record.cleanup_complete_request = Some(updated);
        record.cancellation_cleanup = None;
        record.cleanup_response_trust = Some(pin);
        record.phase = CancelPhaseV1::CleanupCompletePrepared;
        crate::cancel_state_capacity::rebalance(record, before)
    })
}

fn update(
    state: &DurableSecurityState,
    operation: &str,
    now: u64,
    change: impl FnOnce(
        &mut CancelRecordV1,
        crate::cancel_state_capacity::Checkpoint,
    ) -> Result<(), AgentError>,
) -> Result<Box<CancelRecordV1>, AgentError> {
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = crate::source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        let before = crate::cancel_state_capacity::checkpoint(record)?;
        record.updated_at_epoch_s = now;
        change(record, before)?;
        crate::source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn exact(
    value: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<
    crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    AgentError,
>{
    let wire = serde_json::to_vec(value).map_err(|_| AgentError::AuthorityRollback)?;
    decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)
}

fn stable(
    left: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
    right: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<(), AgentError> {
    let left = endpoint_revocation_execution_cancel_cleanup_complete_request_digest(left)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let right = endpoint_revocation_execution_cancel_cleanup_complete_request_digest(right)
        .map_err(|_| AgentError::AuthorityRollback)?;
    (left == right)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn result(
    value: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelCleanupCompleteRequestV1,
) -> Result<String, AgentError> {
    endpoint_revocation_cancellation_acknowledgement_result_digest(value)
        .map_err(|_| AgentError::AuthorityRollback)
}
