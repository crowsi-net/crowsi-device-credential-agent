use crowsi_credential_authority_contracts::ManagementProjectionV2;

use crate::{
    AgentError, VerifiedConfig,
    replay::DurableSecurityState,
    source_approve_state_types::{SourceApprovePhaseV1, SourceApproveResume},
    source_options_state,
};

pub(crate) fn complete(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    operation: &str,
    response_wire: &[u8],
    response: &ManagementProjectionV2,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
    if response_wire.len() > source_options_state::MAXIMUM_PHASE_WIRE_BYTES {
        return Err(AgentError::ResponseInvalid);
    }
    let response_json = std::str::from_utf8(response_wire)
        .map_err(|_| AgentError::ResponseInvalid)?
        .to_owned();
    state.transaction_namespaces(|values| {
        let (mut prepared, mut fresh, mut journal) = source_options_state::documents(values)?;
        {
            let record = journal
                .source_approvals
                .get_mut(operation)
                .ok_or(AgentError::AuthorityRollback)?;
            if record.phase == SourceApprovePhaseV1::Complete {
                let same = record.response.as_ref() == Some(response)
                    && record.response_json.as_deref() == Some(&response_json);
                if same {
                    return unchanged(operation, &prepared, &fresh, &journal);
                }
                if !record.response.as_ref().is_some_and(|expected| {
                    crate::retired_request_refresh_independent::compatible(
                        &expected.body,
                        &response.body,
                    )
                }) {
                    return Err(AgentError::AuthorityResponseInvalid);
                }
            } else if record.phase != SourceApprovePhaseV1::FinalizeUnknown {
                return Err(AgentError::OperationReplay);
            }
            record.phase = SourceApprovePhaseV1::Complete;
            record.response_json = Some(response_json);
            record.response = Some(response.clone());
            record.updated_at_epoch_s = now;
        }
        let result = crate::source_approve_state::resume(operation, &prepared, &fresh, &journal)?;
        crate::operation_artifact_cleanup::terminal_projection(
            response,
            &mut prepared,
            &mut fresh,
            &mut journal,
            now,
        )?;
        source_options_state::validate(&prepared, &fresh, &journal)?;
        crate::management_state::observe_in_transaction(values, response)?;
        crate::identity_locator_io::observe_projection_in(values, &config.0, response, now)?;
        values.put("prepared-operation", &prepared)?;
        values.put("fresh-uv-attempt", &fresh)?;
        values.put("operation-journal", &journal)?;
        Ok((result, true))
    })
}

fn unchanged(
    operation: &str,
    prepared: &crate::source_options_state_types::PreparedOperationsV1,
    fresh: &crate::source_options_state_types::FreshUvAttemptsV1,
    journal: &crate::source_options_state_types::OperationJournalV1,
) -> Result<(SourceApproveResume, bool), AgentError> {
    Ok((
        crate::source_approve_state::resume(operation, prepared, fresh, journal)?,
        false,
    ))
}
