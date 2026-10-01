use crowsi_credential_authority_contracts::ManagementProjectionV2;

use crate::{
    AgentError,
    replay::DurableSecurityState,
    source_options_state,
    target_approve_state_types::{TargetApprovePhaseV1, TargetApproveResume},
};

pub(crate) fn complete(
    state: &DurableSecurityState,
    operation: &str,
    wire: &[u8],
    response: &ManagementProjectionV2,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    let wire = bounded(wire)?;
    state.transaction_namespaces(|values| {
        let (prepared, fresh, mut journal) = source_options_state::documents(values)?;
        let record = journal
            .target_approvals
            .get_mut(operation)
            .ok_or(AgentError::AuthorityRollback)?;
        if record.phase == TargetApprovePhaseV1::Complete {
            let exact = record.response.as_ref() == Some(response)
                && record.response_json.as_deref() == Some(wire.as_str());
            if exact {
                let result =
                    crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
                return Ok((result, false));
            }
            record.response_json = Some(wire);
            record.response = Some(response.clone());
            record.updated_at_epoch_s = now;
            source_options_state::validate(&prepared, &fresh, &journal)?;
            let result =
                crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
            crate::management_state::observe_in_transaction(values, response)?;
            values.put("operation-journal", &journal)?;
            return Ok((result, true));
        }
        if !matches!(
            record.phase,
            TargetApprovePhaseV1::CentralInvoking | TargetApprovePhaseV1::Unknown
        ) {
            return Err(AgentError::OperationReplay);
        }
        if now < record.updated_at_epoch_s {
            return Err(AgentError::AuthorityRollback);
        }
        record.phase = TargetApprovePhaseV1::Complete;
        record.response_json = Some(wire);
        record.response = Some(response.clone());
        record.updated_at_epoch_s = now;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        let result = crate::target_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
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
