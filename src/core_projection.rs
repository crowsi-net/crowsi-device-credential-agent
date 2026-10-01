use crowsi_credential_authority_contracts::{
    ManagementProjectionBinding, ManagementProjectionV2, ManagementRequestV2,
    decode_management_projection_strict, management_command_digest,
    verify_management_projection_at,
};

use crate::{AgentError, VerifiedConfig, replay::DurableSecurityState};

pub(super) fn decode_and_verify(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    request: &ManagementRequestV2,
    response: &[u8],
    now: u64,
) -> Result<ManagementProjectionV2, AgentError> {
    let projection = decode_management_projection_strict(response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = &config.0.management_projection_trust;
    let locator = state.identity_locator().load(&config.0)?;
    let minima = projection.subject_revocation_epoch >= trust.minimum_subject_revocation_epoch
        && projection.service_revocation_epoch >= trust.minimum_service_revocation_epoch
        && projection.device_revocation_epoch >= trust.minimum_device_revocation_epoch
        && projection.session_revocation_epoch >= trust.minimum_session_revocation_epoch
        && projection.device_posture_revision >= trust.minimum_device_posture_revision;
    if !minima {
        return Err(AgentError::AuthorityRollback);
    }
    let digest = management_command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
    let binding = ManagementProjectionBinding {
        request_id: &request.request_id,
        command_digest_sha256: &digest,
        issuer: &trust.issuer,
        audience: &trust.audience,
        service_id: &trust.service_id,
        pairwise_subject: &trust.pairwise_subject,
        opaque_account_ref: &trust.opaque_account_ref,
        current_device_ref: &trust.current_device_ref,
        current_session_ref: &locator.session_ref,
        subject_revocation_epoch: locator.subject_revocation_epoch,
        service_revocation_epoch: locator.service_revocation_epoch,
        device_revocation_epoch: locator.device_revocation_epoch,
        session_revocation_epoch: locator.session_revocation_epoch,
        device_posture_state: &trust.device_posture_state,
        device_posture_revision: locator.device_posture_revision,
        device_proof_key_ref: &trust.device_proof_key_ref,
        minimum_snapshot_revision: trust.minimum_snapshot_revision,
    };
    verify_management_projection_at(
        &projection,
        &binding,
        &trust.key_id,
        &trust.public_key_hex,
        now,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    Ok(projection)
}
