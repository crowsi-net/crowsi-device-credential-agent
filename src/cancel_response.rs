use crowsi_credential_authority_contracts::{
    ManagementRequestV2, decode_endpoint_management_envelope_strict,
};

use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelRecordV1, replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(crate) enum CancelInvokeOutcome {
    Continue(Box<CancelRecordV1>),
    Complete(Vec<u8>),
}

pub(crate) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: Box<CancelRecordV1>,
    now: u64,
) -> Result<CancelInvokeOutcome, AgentError> {
    let operation = &value.operation_id;
    let stored = value
        .central_envelope
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let wire = serde_json::to_vec(stored).map_err(|_| AgentError::AuthorityRollback)?;
    let envelope = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if envelope.browser_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    crate::cancel_state_phase::invoking(state, operation, now)?;
    let response = match transport.exchange("cancel", &wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::cancel_state_phase::unknown(state, operation, now)?;
            return Err(error);
        }
    };
    crate::cancel_state_phase::unknown(state, operation, now)?;
    let projection =
        crate::cancel_verify::response(config, state, browser, &value, &response, now)?;
    let execution = crate::cancel_execution_request::build(&value, &projection)?;
    if let Some(request) = execution {
        let next = crate::cancel_state_execution_prepare::persist(
            state,
            operation,
            &response,
            &projection,
            &request,
            now,
        )?;
        Ok(CancelInvokeOutcome::Continue(next))
    } else {
        crate::cancel_state_response::complete(state, operation, &response, &projection, now)?;
        Ok(CancelInvokeOutcome::Complete(response))
    }
}

pub(crate) fn completed(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &CancelRecordV1,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let projection = crate::cancel_state_wire::response_value(value)?;
    if projection
        .as_ref()
        .is_some_and(|projection| now < projection.expires_at_epoch_s)
    {
        return cached(config, state, browser, value, now);
    }
    refresh(config, state, transport, browser, value, now)
}

fn cached(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &CancelRecordV1,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let response = value
        .response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes()
        .to_vec();
    crate::cancel_verify::response(config, state, browser, value, &response, now)?;
    Ok(response)
}

fn refresh(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &CancelRecordV1,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let stored = value
        .central_envelope
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let envelope = serde_json::to_vec(stored).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_management_envelope_strict(&envelope)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if decoded.browser_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    let response = transport.exchange("cancel", &envelope, now)?;
    let projection = crate::cancel_verify::response(config, state, browser, value, &response, now)?;
    crate::cancel_state_response::complete(
        state,
        &value.operation_id,
        &response,
        &projection,
        now,
    )?;
    Ok(response)
}
