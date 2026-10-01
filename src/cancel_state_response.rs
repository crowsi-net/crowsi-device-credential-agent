use crowsi_credential_authority_contracts::ManagementProjectionV2;

use crate::{
    AgentError, cancel_state_types::CancelPhaseV1, replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn complete(
    state: &DurableSecurityState,
    operation: &str,
    response_wire: &[u8],
    response: &ManagementProjectionV2,
    now: u64,
) -> Result<(), AgentError> {
    if response_wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    std::str::from_utf8(response_wire).map_err(|_| AgentError::ResponseInvalid)?;
    state.transaction_namespaces(|values| {
        let (mut prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .cancellations
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if !matches!(
            record.phase,
            CancelPhaseV1::CentralInvoking | CancelPhaseV1::Unknown
        ) {
            return Err(AgentError::OperationReplay);
        }
        record.phase = CancelPhaseV1::Complete;
        record.cancelled_projection_body = Some(response.body.clone());
        record.response_json = None;
        record.response = None;
        record.updated_at_epoch_s = now;
        crate::cancel_state_cleanup::terminal(
            operation,
            &mut prepared,
            &mut fresh,
            &mut journal,
            now,
        )?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok(((), true))
    })
}
