use crowsi_credential_authority_contracts::{
    ManagementRequestV2, decode_endpoint_management_envelope_strict,
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
        .central_envelope_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let envelope = decode_endpoint_management_envelope_strict(wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if envelope.browser_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    crate::source_approve_state_phase::invoking(state, operation, now)?;
    let response = match transport.exchange("source-approve", wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::source_approve_state_phase::unknown(state, operation, now)?;
            return Err(error);
        }
    };
    crate::source_approve_state_phase::unknown(state, operation, now)?;
    let projection = verify(config, state, browser, &value, &response, now)?;
    crate::source_approve_state_response::complete(state, operation, &response, &projection, now)?;
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
    let projection = value
        .approval
        .response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if now >= projection.expires_at_epoch_s {
        return refresh(config, state, transport, browser, value, now);
    }
    let response = value
        .approval
        .response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes()
        .to_vec();
    verify(config, state, browser, value, &response, now)?;
    Ok(response)
}

fn refresh(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &SourceApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let envelope = value
        .approval
        .central_envelope_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let decoded = decode_endpoint_management_envelope_strict(envelope)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if decoded.browser_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    let response = transport.exchange("source-approve", envelope, now)?;
    let projection = verify(config, state, browser, value, &response, now)?;
    crate::source_approve_state_response::complete(
        state,
        &value.source.prepared.operation_id,
        &response,
        &projection,
        now,
    )?;
    Ok(response)
}

pub(crate) fn verify(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &SourceApproveResume,
    response: &[u8],
    now: u64,
) -> Result<crowsi_credential_authority_contracts::ManagementProjectionV2, AgentError> {
    let projection =
        crate::core_projection::decode_and_verify(config, state, browser, response, now)?;
    crate::source_approve_response_verify::exact(value, &projection)?;
    Ok(projection)
}
