use crowsi_credential_authority_contracts::{
    ManagementRequestV2, decode_endpoint_management_envelope_strict,
};

use crate::{
    AgentError, VerifiedConfig, replay::DurableSecurityState,
    target_approve_state_types::TargetApproveResume, transport::AuthorityTransport,
};

pub(crate) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: TargetApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let operation = &value.approval.operation_id;
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
    crate::target_approve_state_phase::central_invoking(state, operation, now)?;
    let response = match transport.exchange("target-approve", wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::target_approve_state_phase::central_unknown(state, operation, now)?;
            return Err(error);
        }
    };
    crate::target_approve_state_phase::central_unknown(state, operation, now)?;
    let projection = verify(config, state, browser, &value, &response, now)?;
    crate::target_approve_state_response::complete(state, operation, &response, &projection, now)?;
    Ok(response)
}

pub(crate) fn completed(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &TargetApproveResume,
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
    let wire = value
        .approval
        .response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes()
        .to_vec();
    verify(config, state, browser, value, &wire, now)?;
    Ok(wire)
}

fn refresh(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &TargetApproveResume,
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
    let response = transport.exchange("target-approve", envelope, now)?;
    let projection = verify(config, state, browser, value, &response, now)?;
    crate::target_approve_state_response::complete(
        state,
        &value.approval.operation_id,
        &response,
        &projection,
        now,
    )?;
    Ok(response)
}

fn verify(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &TargetApproveResume,
    wire: &[u8],
    now: u64,
) -> Result<crowsi_credential_authority_contracts::ManagementProjectionV2, AgentError> {
    let projection = crate::core_projection::decode_and_verify(config, state, browser, wire, now)?;
    crate::target_approve_projection::exact(value, &projection)?;
    Ok(projection)
}
