use crowsi_credential_authority_contracts::{
    ManagementRequestV2, decode_endpoint_management_envelope_strict,
};

use crate::{
    AgentError, VerifiedConfig, replay::DurableSecurityState,
    source_options_state::SourceOptionsResume, transport::AuthorityTransport,
};

pub(crate) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: SourceOptionsResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let operation = &value.prepared.prepared.operation_id;
    let envelope_wire = value
        .journal
        .central_envelope_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let envelope = decode_endpoint_management_envelope_strict(envelope_wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if envelope.browser_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    crate::source_options_state_transition::invoking(state, operation, now)?;
    let response = match transport.exchange("source-options", envelope_wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::source_options_state_transition::unknown(state, operation, now)?;
            return Err(error);
        }
    };
    crate::source_options_state_transition::unknown(state, operation, now)?;
    verify_and_complete(config, state, browser, &value, &response, now)?;
    Ok(response)
}

pub(crate) fn completed(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &SourceOptionsResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let projection = value
        .journal
        .response
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if now >= projection.expires_at_epoch_s {
        return refresh(config, state, transport, browser, value, now);
    }
    let response = value
        .journal
        .response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes()
        .to_vec();
    verify_response(config, state, browser, value, &response, now)?;
    Ok(response)
}

fn refresh(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &SourceOptionsResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let envelope = value
        .journal
        .central_envelope_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let decoded = decode_endpoint_management_envelope_strict(envelope)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if decoded.browser_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    let response = transport.exchange("source-options", envelope, now)?;
    verify_and_complete(config, state, browser, value, &response, now)?;
    Ok(response)
}

fn verify_and_complete(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &SourceOptionsResume,
    response: &[u8],
    now: u64,
) -> Result<(), AgentError> {
    let projection = verify_response(config, state, browser, value, response, now)?;
    crate::source_options_state_response::complete(
        state,
        &value.prepared.prepared.operation_id,
        response,
        &projection,
        now,
    )?;
    Ok(())
}

fn verify_response(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &SourceOptionsResume,
    response: &[u8],
    now: u64,
) -> Result<crowsi_credential_authority_contracts::ManagementProjectionV2, AgentError> {
    let projection =
        crate::core_projection::decode_and_verify(config, state, browser, response, now)?;
    let begin = value
        .fresh_uv
        .exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    crate::source_options_verify::projection(
        &value.prepared.prepared,
        begin,
        expected_revision(&value.prepared.prepared.intent),
        &projection,
    )?;
    crate::source_options_scope::validate(
        &value.prepared.prepared,
        &value.prepared.expected_operation_kind,
        &value.prepared.expected_operation_scope,
        &projection,
    )?;
    Ok(projection)
}

include!("source_options_response_revision.rs");
