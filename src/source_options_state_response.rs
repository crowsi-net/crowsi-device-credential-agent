use crowsi_credential_authority_contracts::ManagementProjectionV2;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_options_state::{self, SourceOptionsPhaseV1, SourceOptionsResume},
};

pub(crate) fn complete(
    state: &DurableSecurityState,
    operation: &str,
    response_wire: &[u8],
    response: &ManagementProjectionV2,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    if response_wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    let response_json = std::str::from_utf8(response_wire)
        .map_err(|_| AgentError::ResponseInvalid)?
        .to_owned();
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .records
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase == SourceOptionsPhaseV1::Complete {
            let same = record.response.as_ref() == Some(response)
                && record.response_json.as_deref() == Some(&response_json);
            if same {
                let result = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
                return Ok((result, false));
            }
            record.response_json = Some(response_json);
            record.response = Some(response.clone());
            record.updated_at_epoch_s = now;
            source_options_state::validate(&prepared, &fresh, &journal)?;
            let result = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
            crate::management_state::observe_in_transaction(values, response)?;
            values.put("operation-journal", &journal)?;
            return Ok((result, true));
        }
        if !matches!(
            record.phase,
            SourceOptionsPhaseV1::CentralInvoking | SourceOptionsPhaseV1::Unknown
        ) {
            return Err(AgentError::OperationReplay);
        }
        record.phase = SourceOptionsPhaseV1::Complete;
        record.response_json = Some(response_json);
        record.response = Some(response.clone());
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = source_options_state::resume(operation, &prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}
