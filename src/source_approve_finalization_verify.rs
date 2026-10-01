use crowsi_credential_authority_contracts::{
    EndpointRevocationFinalizeProjectionTrustV1, ManagementProjectionV2,
    decode_management_projection_strict, verify_endpoint_revocation_finalize_projection_at,
};

use crate::{AgentError, VerifiedConfig, source_approve_state_types::SourceApproveResume};

pub(crate) fn response(
    config: &VerifiedConfig,
    value: &SourceApproveResume,
    wire: &[u8],
    now: u64,
) -> Result<ManagementProjectionV2, AgentError> {
    let request = value
        .approval
        .revocation_finalize_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    if request.source_approve_request != value.approval.browser_request {
        return Err(AgentError::AuthorityRollback);
    }
    request_response(config, request, wire, now)
}

pub(crate) fn request_response(
    config: &VerifiedConfig,
    request: &crowsi_credential_authority_contracts::EndpointRevocationFinalizeRequestV1,
    wire: &[u8],
    now: u64,
) -> Result<ManagementProjectionV2, AgentError> {
    let projection = decode_management_projection_strict(wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = &config.0.management_projection_trust;
    verify_endpoint_revocation_finalize_projection_at(
        &projection,
        request,
        &config.0.authority_route.device_id,
        &EndpointRevocationFinalizeProjectionTrustV1 {
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
