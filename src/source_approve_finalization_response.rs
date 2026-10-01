use crowsi_credential_authority_contracts::{
    ManagementRequestV2, decode_endpoint_revocation_finalize_request_strict,
};

use crate::{
    AgentError, VerifiedConfig, replay::DurableSecurityState,
    source_approve_state_types::SourceApproveResume, transport::AuthorityTransport,
};

pub(crate) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: SourceApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let operation = &value.source.prepared.operation_id;
    let wire = value
        .approval
        .revocation_finalize_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let request = decode_endpoint_revocation_finalize_request_strict(wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if value.approval.revocation_finalize_request.as_ref() != Some(&request)
        || request.source_approve_request != *browser
    {
        return Err(AgentError::AuthorityRollback);
    }
    crate::source_approve_finalization_phase::invoking(state, operation, now)?;
    let response = match transport.exchange("revocation-finalize", wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::source_approve_finalization_phase::unknown(state, operation, now)?;
            return Err(error);
        }
    };
    crate::source_approve_finalization_phase::unknown(state, operation, now)?;
    let projection =
        crate::source_approve_finalization_verify::response(config, &value, &response, now)?;
    crate::source_approve_state_final_response::complete(
        config,
        state,
        operation,
        &response,
        &projection,
        now,
    )?;
    Ok(response)
}

pub(crate) fn completed(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &SourceApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let response = value
        .approval
        .response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes()
        .to_vec();
    if value.approval.browser_request != *browser {
        return Err(AgentError::OperationReplay);
    }
    if crate::source_approve_finalization_verify::response(config, value, &response, now).is_ok() {
        return Ok(response);
    }
    let request_wire = value
        .approval
        .revocation_finalize_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = decode_endpoint_revocation_finalize_request_strict(request_wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    if request.source_approve_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    let fresh = transport.exchange("revocation-finalize", request_wire.as_bytes(), now)?;
    let projection =
        crate::source_approve_finalization_verify::response(config, value, &fresh, now)?;
    let compatible = value.approval.response.as_ref().is_some_and(|expected| {
        crate::retired_request_refresh_independent::compatible(&expected.body, &projection.body)
    });
    if !compatible {
        return Err(AgentError::AuthorityResponseInvalid);
    }
    crate::source_approve_state_final_response::complete(
        config,
        state,
        &value.source.prepared.operation_id,
        &fresh,
        &projection,
        now,
    )?;
    Ok(fresh)
}
