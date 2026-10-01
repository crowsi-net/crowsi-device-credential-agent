use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelRequestV1, ManagementProjectionV2,
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
    response_wire: &[u8],
    response: &ManagementProjectionV2,
    request: &EndpointRevocationExecutionCancelRequestV1,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    bounded(response_wire)?;
    if serde_json::to_vec(request)
        .map_err(|_| AgentError::RequestInvalid)?
        .len()
        > source_options_state::MAXIMUM_PHASE_WIRE_BYTES
    {
        return Err(AgentError::RequestInvalid);
    }
    state.transaction_namespaces(|values| {
        let (mut prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        let before = journal
            .cancellations
            .get(operation)
            .ok_or(AgentError::AuthorityRollback)
            .and_then(|record| crate::cancel_state_capacity::checkpoint(record))?;
        if !journal.cancellations.get(operation).is_some_and(|record| {
            matches!(
                record.phase,
                CancelPhaseV1::CentralInvoking | CancelPhaseV1::Unknown
            )
        }) {
            return Err(AgentError::OperationReplay);
        }
        crate::cancel_state_cleanup::operation(
            operation,
            &mut prepared,
            &mut fresh,
            &mut journal,
            now,
        )?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        record.response_json = None;
        record.response = None;
        record.cancelled_projection_body = Some(response.body.clone());
        record.execution_cancel_request = Some(Box::new(request.clone()));
        record.current_exchange = None;
        record.current_observed_at_epoch_s = None;
        record.lookup_request = None;
        record.lookup_response = None;
        record.revocation_begin_exchange = None;
        record.pre_final_acceptance_request_sha256 = None;
        record.phase = CancelPhaseV1::ExecutionCancelPrepared;
        record.expires_at_epoch_s = crate::cancel_state::expiration(record)?;
        record.updated_at_epoch_s = now;
        crate::cancel_state_capacity::rebalance(record, before)?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::cancel_state::resume(operation, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
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
