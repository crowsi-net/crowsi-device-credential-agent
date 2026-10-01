use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancellationCleanupV1,
    verify_endpoint_revocation_execution_cancellation_cleanup_historic,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{
    AgentError,
    cancel_state_types::{CancelCentralTrustPinV1, CancelPhaseV1, CancelRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(super) fn persist(
    state: &DurableSecurityState,
    operation: &str,
    wire: &[u8],
    cleanup: &EndpointRevocationExecutionCancellationCleanupV1,
    pin: CancelCentralTrustPinV1,
    acknowledge: &AuthorityRequestV1,
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
        if record.phase != CancelPhaseV1::CancelFinalizeUnknown {
            return Err(AgentError::OperationReplay);
        }
        let request = record
            .cancel_finalize_request
            .as_ref()
            .ok_or(AgentError::AuthorityRollback)?;
        let cancellation = &request.cancellation;
        verify_endpoint_revocation_execution_cancellation_cleanup_historic(
            cleanup,
            request,
            cancellation,
            &pin.peer_device_ref,
            &crate::cancel_central_trust::cleanup_historic(&pin),
        )
        .map_err(|_| AgentError::AuthorityRollback)?;
        record.cancellation_cleanup = Some(cleanup.clone());
        record.cancellation_cleanup_trust = Some(pin);
        if &crowsi_credential_authority_contracts::attach_revocation_cancellation_cleanup(
            &cleanup.acknowledge_request,
            cleanup,
        )
        .map_err(|_| AgentError::AuthorityRollback)?
            != acknowledge
        {
            return Err(AgentError::AuthorityRollback);
        }
        record.phase = CancelPhaseV1::CleanupAckPrepared;
        record.expires_at_epoch_s = crate::cancel_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        crate::cancel_state_capacity::rebalance(record, before)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
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
