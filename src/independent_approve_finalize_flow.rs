use crate::{
    AgentError, VerifiedConfig, independent_approve_state_types::IndependentApproveResume,
    replay::DurableSecurityState, transport::AuthorityTransport,
};
use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationFinalizeProjectionTrustV1,
    decode_endpoint_independent_revocation_finalize_request_strict,
    decode_management_projection_strict,
    verify_endpoint_independent_revocation_finalize_projection_at,
};
pub(super) fn prepare(
    state: &DurableSecurityState,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let request = crate::independent_approve_finalize_request::build(&value)?;
    crate::independent_approve_state_ceremony::finalize_prepared(
        state,
        &value.approval.operation_id,
        &request,
        now,
    )
}
pub(super) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &crowsi_credential_authority_contracts::ManagementRequestV2,
    value: IndependentApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::independent_approve_state_phase::finalize_invoking(state, &operation, now)?;
    let (wire, request) = exact(browser, &invoking)?;
    let response = transport.exchange("independent-revocation-finalize", wire, now);
    let response = match response {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::finalize_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::finalize_unknown(state, &operation, now)?;
    let projection = request_response(config, &request, &response, now)?;
    crate::independent_approve_state_response::complete(
        config,
        state,
        &operation,
        &response,
        &projection,
        now,
    )?;
    Ok(response)
}

pub(super) fn completed<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &crowsi_credential_authority_contracts::ManagementRequestV2,
    value: &IndependentApproveResume,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    let response = value
        .approval
        .response_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes()
        .to_vec();
    let (_, request) = exact(browser, value)?;
    if request_response(config, &request, &response, now).is_ok() {
        return Ok(response);
    }
    let wire = value
        .approval
        .finalize_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let fresh = transport.exchange("independent-revocation-finalize", wire, now)?;
    let projection = request_response(config, &request, &fresh, now)?;
    let compatible = value.approval.response.as_ref().is_some_and(|expected| {
        crate::retired_request_refresh_independent::compatible(&expected.body, &projection.body)
    });
    if !compatible {
        return Err(AgentError::AuthorityResponseInvalid);
    }
    crate::independent_approve_state_response::complete(
        config,
        state,
        &value.approval.operation_id,
        &fresh,
        &projection,
        now,
    )?;
    Ok(fresh)
}

fn exact<'a>(
    browser: &crowsi_credential_authority_contracts::ManagementRequestV2,
    value: &'a IndependentApproveResume,
) -> Result<
    (
        &'a [u8],
        crowsi_credential_authority_contracts::EndpointIndependentRevocationFinalizeRequestV1,
    ),
    AgentError,
> {
    let wire = value
        .approval
        .finalize_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let request = decode_endpoint_independent_revocation_finalize_request_strict(wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let same = value.approval.finalize_request.as_ref() == Some(&request)
        && request.approve_revocation_request == *browser;
    same.then_some((wire, request))
        .ok_or(AgentError::AuthorityRollback)
}

pub(crate) fn request_response(
    config: &VerifiedConfig,
    request: &crowsi_credential_authority_contracts::EndpointIndependentRevocationFinalizeRequestV1,
    wire: &[u8],
    now: u64,
) -> Result<crowsi_credential_authority_contracts::ManagementProjectionV2, AgentError> {
    let projection = decode_management_projection_strict(wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = &config.0.management_projection_trust;
    verify_endpoint_independent_revocation_finalize_projection_at(
        &projection,
        request,
        &config.0.authority_route.device_id,
        &EndpointIndependentRevocationFinalizeProjectionTrustV1 {
            issuer: &trust.issuer,
            audience: &trust.audience,
            key_id: &trust.key_id,
            public_key_hex: &trust.public_key_hex,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    Ok(projection)
}
