use std::path::Path;

use crate::{AgentError, VerifiedConfig, identity_locator::IdentitySessionLocatorV1};

pub(crate) fn initialize_locator(
    config: &VerifiedConfig,
    session_ref: &str,
    now: u64,
    expected_uid: u32,
) -> Result<(), AgentError> {
    let value = &config.0;
    let trust = &value.management_projection_trust;
    let state = crate::replay::DurableSecurityState::open(
        Path::new(&value.endpoint_state_directory),
        Path::new(&value.endpoint_anchor_directory),
        expected_uid,
        &value.endpoint_deployment_id,
        value.configuration_generation,
    )?;
    state
        .identity_locator()
        .create_value(&IdentitySessionLocatorV1 {
            schema: "crowsi://device-credential-agent/identity-session-locator/v2".into(),
            issuer: value.identity_issuer.clone(),
            service_id: trust.service_id.clone(),
            pairwise_subject: trust.pairwise_subject.clone(),
            device_id: value.identity_authority_route.device_id.clone(),
            session_ref: session_ref.into(),
            sender_key_fingerprint: value.session_sender_key_fingerprint.clone(),
            subject_revocation_epoch: trust.minimum_subject_revocation_epoch,
            service_revocation_epoch: trust.minimum_service_revocation_epoch,
            device_revocation_epoch: trust.minimum_device_revocation_epoch,
            session_revocation_epoch: trust.minimum_session_revocation_epoch,
            device_posture_state: trust.device_posture_state.clone(),
            device_posture_revision: trust.minimum_device_posture_revision,
            device_proof_key_ref: trust.device_proof_key_ref.clone(),
            response_config_generation: value.minimum_identity_config_generation,
            response_command_digest: "0".repeat(64),
            authority_issued_at_epoch_s: now.saturating_sub(2),
            updated_at_epoch_s: now.saturating_sub(2),
        })
}
