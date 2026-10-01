use crate::{AgentError, config::AgentConfigDocument, identity_locator::IdentitySessionLocatorV1};
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

pub(super) fn exact(
    config: &AgentConfigDocument,
    value: &IdentitySessionLocatorV1,
) -> Result<(), AgentError> {
    historic(config, value)?;
    (value.response_config_generation >= config.minimum_identity_config_generation)
        .then_some(())
        .ok_or(AgentError::IdentityUnavailable)
}

pub(crate) fn historic(
    config: &AgentConfigDocument,
    value: &IdentitySessionLocatorV1,
) -> Result<(), AgentError> {
    let trust = &config.management_projection_trust;
    let valid = value.schema == "crowsi://device-credential-agent/identity-session-locator/v2"
        && value.issuer == config.identity_issuer
        && value.service_id == trust.service_id
        && value.pairwise_subject == trust.pairwise_subject
        && value.device_id == config.identity_authority_route.device_id
        && session_ref(&value.session_ref)
        && value.sender_key_fingerprint == config.session_sender_key_fingerprint
        && value.subject_revocation_epoch >= trust.minimum_subject_revocation_epoch
        && value.service_revocation_epoch >= trust.minimum_service_revocation_epoch
        && value.device_revocation_epoch >= trust.minimum_device_revocation_epoch
        && value.session_revocation_epoch >= trust.minimum_session_revocation_epoch
        && value.device_posture_state == trust.device_posture_state
        && value.device_posture_revision >= trust.minimum_device_posture_revision
        && value.device_proof_key_ref == trust.device_proof_key_ref
        && lower_hex(&value.response_command_digest)
        && value.authority_issued_at_epoch_s > 0
        && value.updated_at_epoch_s >= value.authority_issued_at_epoch_s;
    valid.then_some(()).ok_or(AgentError::IdentityUnavailable)
}

pub(crate) fn current(
    old: &IdentitySessionLocatorV1,
    new: &IdentitySessionLocatorV1,
) -> Result<(), AgentError> {
    if new == old || exact_observation(old, new) {
        return Ok(());
    }
    let invalid = new.issuer != old.issuer
        || new.service_id != old.service_id
        || new.pairwise_subject != old.pairwise_subject
        || new.device_id != old.device_id
        || new.session_ref != old.session_ref
        || new.sender_key_fingerprint != old.sender_key_fingerprint
        || new.device_proof_key_ref != old.device_proof_key_ref
        || new.subject_revocation_epoch < old.subject_revocation_epoch
        || new.service_revocation_epoch < old.service_revocation_epoch
        || new.device_revocation_epoch < old.device_revocation_epoch
        || new.session_revocation_epoch < old.session_revocation_epoch
        || new.device_posture_revision < old.device_posture_revision
        || new.response_config_generation < old.response_config_generation
        || new.authority_issued_at_epoch_s <= old.authority_issued_at_epoch_s
        || new.updated_at_epoch_s < old.updated_at_epoch_s;
    (!invalid)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

pub(crate) fn same_identity(
    locator: &IdentitySessionLocatorV1,
    identity: &IdentityEvidenceMetadata,
) -> bool {
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    locator.issuer == assertion.issuer
        && locator.service_id == assertion.service_id
        && locator.pairwise_subject == assertion.pairwise_subject
        && locator.device_id == assertion.device_id
        && locator.session_ref == assertion.session_ref
        && locator.subject_revocation_epoch == epochs.subject
        && locator.service_revocation_epoch == epochs.service
        && locator.device_revocation_epoch == epochs.device
        && locator.session_revocation_epoch == epochs.session
        && locator.device_posture_state == assertion.device_posture.state
        && locator.device_posture_revision == assertion.device_posture.revision
        && locator.device_proof_key_ref == assertion.device_proof_key_ref
}

fn exact_observation(old: &IdentitySessionLocatorV1, new: &IdentitySessionLocatorV1) -> bool {
    let mut replay = old.clone();
    replay.updated_at_epoch_s = new.updated_at_epoch_s;
    replay == *new && new.updated_at_epoch_s >= old.updated_at_epoch_s
}

fn session_ref(value: &str) -> bool {
    value.len() == 69 && value.starts_with("sref_") && lower_hex(&value[5..])
}
fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
