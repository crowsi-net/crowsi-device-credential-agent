use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationPreFinalProjectionTrustV1,
    decode_endpoint_independent_revocation_pre_final_request_strict,
    decode_management_projection_strict,
    verify_endpoint_independent_revocation_pre_final_projection_at,
};

use crate::{
    AgentError, VerifiedConfig,
    independent_approve_state_types::{IndependentApproveResume, IndependentProjectionTrustPinV1},
    replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(super) fn prepare(
    state: &DurableSecurityState,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let request = crate::independent_approve_pre_final_request::build(
        &value,
        crate::random_id::create("independent-revocation-pre-final")?,
    )?;
    crate::independent_approve_state_pre_final::prepared(
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
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::independent_approve_state_phase::pre_final_invoking(state, &operation, now)?;
    let (wire, request) = exact(&invoking)?;
    let response = transport.exchange("independent-revocation-pre-final", wire, now);
    let response = match response {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::pre_final_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::pre_final_unknown(state, &operation, now)?;
    let projection = decode_management_projection_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = pin(config, now);
    verify_endpoint_independent_revocation_pre_final_projection_at(
        &projection,
        &request,
        &trust.peer_device_ref,
        &EndpointIndependentRevocationPreFinalProjectionTrustV1 {
            issuer: &trust.issuer,
            audience: &trust.audience,
            key_id: &trust.key_id,
            public_key_hex: &trust.public_key_hex,
            minimum_snapshot_revision: trust.minimum_snapshot_revision,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::independent_approve_state_pre_final::accepted(
        state,
        &operation,
        &response,
        &projection,
        trust,
        now,
    )
}

fn exact(
    value: &IndependentApproveResume,
) -> Result<
    (
        &[u8],
        crowsi_credential_authority_contracts::EndpointIndependentRevocationPreFinalRequestV1,
    ),
    AgentError,
> {
    let wire = value
        .approval
        .pre_final_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let request = decode_endpoint_independent_revocation_pre_final_request_strict(wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.approval.pre_final_request.as_ref() == Some(&request))
        .then_some((wire, request))
        .ok_or(AgentError::AuthorityRollback)
}

fn pin(config: &VerifiedConfig, now: u64) -> IndependentProjectionTrustPinV1 {
    let trust = &config.0.management_projection_trust;
    IndependentProjectionTrustPinV1 {
        issuer: trust.issuer.clone(),
        audience: trust.audience.clone(),
        key_id: trust.key_id.clone(),
        public_key_hex: trust.public_key_hex.clone(),
        minimum_snapshot_revision: trust.minimum_snapshot_revision,
        peer_device_ref: config.0.authority_route.device_id.clone(),
        accepted_at_epoch_s: now,
    }
}
