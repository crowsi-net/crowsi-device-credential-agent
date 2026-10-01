use crowsi_credential_authority_contracts::ManagementProjectionV2;

use crate::{AgentError, VerifiedConfig, replay::DurableSecurityState};

pub(super) fn locator(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    value: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let locator = state.identity_locator().load(&config.0)?;
    let exact = value.current_device_ref == locator.device_id
        && value.current_session_ref == locator.session_ref
        && value.subject_revocation_epoch >= locator.subject_revocation_epoch
        && value.service_revocation_epoch >= locator.service_revocation_epoch
        && value.device_revocation_epoch >= locator.device_revocation_epoch
        && value.session_revocation_epoch >= locator.session_revocation_epoch
        && value.device_posture_state == locator.device_posture_state
        && value.device_posture_revision >= locator.device_posture_revision
        && value.device_proof_key_ref == locator.device_proof_key_ref;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

pub(super) fn projection(
    trust: &crate::config::ManagementProjectionTrust,
    value: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    let exact = value.subject_revocation_epoch >= trust.minimum_subject_revocation_epoch
        && value.service_revocation_epoch >= trust.minimum_service_revocation_epoch
        && value.device_revocation_epoch >= trust.minimum_device_revocation_epoch
        && value.session_revocation_epoch >= trust.minimum_session_revocation_epoch
        && value.device_posture_state == trust.device_posture_state
        && value.device_posture_revision >= trust.minimum_device_posture_revision
        && value.device_proof_key_ref == trust.device_proof_key_ref;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
