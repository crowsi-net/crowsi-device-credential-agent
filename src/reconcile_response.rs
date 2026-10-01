use crowsi_credential_authority_contracts::{
    ManagementRequestV2, decode_endpoint_management_envelope_strict,
};

use crate::{
    AgentError, VerifiedConfig, reconcile_state_types::ReconcileRecordV1,
    replay::DurableSecurityState, transport::AuthorityTransport,
};

pub(crate) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: ReconcileRecordV1,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let key = &value.browser_request_digest_sha256;
    let wire = envelope(&value, browser)?;
    crate::reconcile_state_phase::central_invoking(state, key, now)?;
    let response = match transport.exchange("reconcile", wire, now) {
        Ok(response) => response,
        Err(error) => {
            crate::reconcile_state_phase::central_unknown(state, key, now)?;
            return Err(error);
        }
    };
    crate::reconcile_state_phase::central_unknown(state, key, now)?;
    verified_complete(config, state, browser, &value, &response, now)
}

pub(crate) fn completed(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &impl AuthorityTransport,
    browser: &ManagementRequestV2,
    value: &ReconcileRecordV1,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let response = value
        .response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes()
        .to_vec();
    if verify(config, state, browser, value, &response, now).is_ok() {
        return Ok(response);
    }
    let envelope = envelope(value, browser)?;
    let response = transport.exchange("reconcile", envelope, now)?;
    verified_complete(config, state, browser, value, &response, now)
}

fn verified_complete(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &ReconcileRecordV1,
    response: &[u8],
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let projection = verify(config, state, browser, value, response, now)?;
    crate::reconcile_state_response::complete(
        config,
        state,
        &value.browser_request_digest_sha256,
        response,
        &projection,
        now,
    )?;
    Ok(response.to_vec())
}

fn verify(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &ReconcileRecordV1,
    response: &[u8],
    now: u64,
) -> Result<crowsi_credential_authority_contracts::ManagementProjectionV2, AgentError> {
    let projection =
        crate::core_projection::decode_and_verify(config, state, browser, response, now)?;
    crate::reconcile_verify::projection(browser, value, &projection)?;
    Ok(projection)
}

fn envelope<'a>(
    value: &'a ReconcileRecordV1,
    browser: &ManagementRequestV2,
) -> Result<&'a [u8], AgentError> {
    let wire = value
        .central_envelope_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let decoded = decode_endpoint_management_envelope_strict(wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    (decoded.browser_request == *browser)
        .then_some(wire)
        .ok_or(AgentError::AuthorityRollback)
}
