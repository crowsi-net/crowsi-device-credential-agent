use crowsi_credential_authority_contracts::{
    EndpointRevocationPreFinalProjectionTrustV1, ManagementOperationState,
    ManagementProjectionBodyV2, ManagementRequestV2, decode_endpoint_management_envelope_strict,
    decode_management_projection_strict, verify_endpoint_revocation_pre_final_projection_at,
};

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_approve_state_types::SourceApproveResume,
    transport::AuthorityTransport,
};

pub(crate) fn invoke<T: AuthorityTransport, I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    browser: &ManagementRequestV2,
    value: SourceApproveResume,
    now: u64,
) -> Result<SourceApproveResume, AgentError> {
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
    let projection = decode_management_projection_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = &config.0.management_projection_trust;
    verify_endpoint_revocation_pre_final_projection_at(
        &projection,
        &envelope,
        &config.0.authority_route.device_id,
        &EndpointRevocationPreFinalProjectionTrustV1 {
            issuer: &trust.issuer,
            audience: &trust.audience,
            key_id: &trust.key_id,
            public_key_hex: &trust.public_key_hex,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::source_approve_response_verify::exact(&value, &projection)?;
    let ManagementProjectionBodyV2::Operation {
        operation: projected,
    } = &projection.body
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    if projected.state != ManagementOperationState::AwaitingRevocationFinal {
        return Err(AgentError::AuthorityResponseInvalid);
    }
    let request_id = crate::random_id::create("revocation-finalize-request")?;
    let current = identity.prepare_current_identity(&config.0, now)?;
    crate::source_approve_state_pre_final::accepted(
        state,
        operation,
        &response,
        &projection,
        &request_id,
        &current,
        now,
    )
}
