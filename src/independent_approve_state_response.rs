use crowsi_credential_authority_contracts::ManagementProjectionV2;

use crate::{
    AgentError, VerifiedConfig,
    independent_approve_state_types::{
        IndependentApprovePhaseV1 as Phase, IndependentApproveResume,
    },
    replay::DurableSecurityState,
};

pub(crate) fn complete(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    operation: &str,
    wire: &[u8],
    response: &ManagementProjectionV2,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let wire = bounded(wire)?;
    state.transaction_namespaces(|values| {
        let (mut prepared, mut fresh, mut journal) =
            crate::source_options_state::documents(values)?;
        {
            let record = journal
                .independent_approvals
                .get_mut(operation)
                .ok_or(AgentError::AuthorityRollback)?;
            if record.phase == Phase::Complete {
                let exact = record.response.as_ref() == Some(response)
                    && record.response_json.as_deref() == Some(wire.as_str());
                if exact {
                    let result = crate::independent_approve_state::resume(
                        operation, &prepared, &fresh, &journal,
                    )?;
                    return Ok((result, false));
                }
                if !record.response.as_ref().is_some_and(|expected| {
                    crate::retired_request_refresh_independent::compatible(
                        &expected.body,
                        &response.body,
                    )
                }) {
                    return Err(AgentError::AuthorityResponseInvalid);
                }
            } else if record.phase != Phase::FinalizeUnknown {
                return Err(AgentError::OperationReplay);
            }
            if now < record.updated_at_epoch_s {
                return Err(AgentError::AuthorityRollback);
            }
            record.phase = Phase::Complete;
            record.response_json = Some(wire);
            record.response = Some(response.clone());
            record.updated_at_epoch_s = now;
        }
        let result =
            crate::independent_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        crate::operation_artifact_cleanup::terminal_projection(
            response,
            &mut prepared,
            &mut fresh,
            &mut journal,
            now,
        )?;
        crate::source_options_state::validate(&prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        crate::identity_locator_io::observe_projection_in(values, &config.0, response, now)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn bounded(wire: &[u8]) -> Result<String, AgentError> {
    if wire.is_empty() || wire.len() > crate::source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    std::str::from_utf8(wire)
        .map(str::to_owned)
        .map_err(|_| AgentError::ResponseInvalid)
}
