use crowsi_credential_authority_contracts::ManagementProjectionV2;

use crate::{
    AgentError, VerifiedConfig,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    replay::DurableSecurityState,
    source_options_state,
};

pub(crate) fn complete(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    key: &str,
    response_wire: &[u8],
    response: &ManagementProjectionV2,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    let response_json = bounded(response_wire)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        {
            let record = journal
                .reconciliations
                .get_mut(key)
                .ok_or(AgentError::AuthorityRollback)?;
            if record.phase == ReconcilePhaseV1::Complete {
                let same = record.response.as_ref() == Some(response)
                    && record.response_json.as_deref() == Some(response_json.as_str());
                if same {
                    let result = crate::reconcile_state::resume(key, &journal)?;
                    return Ok((result, false));
                }
            } else if !matches!(
                record.phase,
                ReconcilePhaseV1::CentralInvoking | ReconcilePhaseV1::Unknown
            ) {
                return Err(AgentError::OperationReplay);
            }
            record.phase = ReconcilePhaseV1::Complete;
            record.response_json = Some(response_json);
            record.response = Some(response.clone());
            record.updated_at_epoch_s = now;
            record.retain_until_epoch_s =
                now.checked_add(600).ok_or(AgentError::AuthorityRollback)?;
        }
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::reconcile_state::resume(key, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        crate::identity_locator_io::observe_projection_in(values, &config.0, response, now)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn bounded(wire: &[u8]) -> Result<String, AgentError> {
    if wire.is_empty() || wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    std::str::from_utf8(wire)
        .map(str::to_owned)
        .map_err(|_| AgentError::ResponseInvalid)
}
