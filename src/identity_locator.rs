use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;
use serde::{Deserialize, Serialize};

use crate::{AgentError, config::AgentConfigDocument, identity_locator_io::IdentityLocatorStore};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentitySessionLocatorV1 {
    pub schema: String,
    pub issuer: String,
    pub service_id: String,
    pub pairwise_subject: String,
    pub device_id: String,
    pub session_ref: String,
    pub sender_key_fingerprint: String,
    pub subject_revocation_epoch: u64,
    pub service_revocation_epoch: u64,
    pub device_revocation_epoch: u64,
    pub session_revocation_epoch: u64,
    pub device_posture_state: String,
    pub device_posture_revision: u64,
    pub device_proof_key_ref: String,
    pub response_config_generation: u64,
    pub response_command_digest: String,
    pub authority_issued_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

impl IdentityLocatorStore<'_> {
    pub(crate) fn load(
        &self,
        config: &AgentConfigDocument,
    ) -> Result<IdentitySessionLocatorV1, AgentError> {
        let value = self.load_value()?.ok_or(AgentError::IdentityUnavailable)?;
        crate::identity_locator_validation::exact(config, &value)?;
        Ok(value)
    }

    pub(crate) fn observe_current_evidence(
        &self,
        config: &AgentConfigDocument,
        expected: &IdentitySessionLocatorV1,
        identity: &IdentityEvidenceMetadata,
        response_generation: u64,
        response_digest: &str,
        now: u64,
    ) -> Result<IdentitySessionLocatorV1, AgentError> {
        let next = build(config, identity, response_generation, response_digest, now);
        crate::identity_locator_validation::exact(config, &next)?;
        self.observe_current_value(expected, &next)?;
        Ok(next)
    }
}

fn build(
    config: &AgentConfigDocument,
    identity: &IdentityEvidenceMetadata,
    response_generation: u64,
    response_digest: &str,
    now: u64,
) -> IdentitySessionLocatorV1 {
    let value = &identity.assertion;
    IdentitySessionLocatorV1 {
        schema: "crowsi://device-credential-agent/identity-session-locator/v2".into(),
        issuer: value.issuer.clone(),
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        device_id: value.device_id.clone(),
        session_ref: value.session_ref.clone(),
        sender_key_fingerprint: config.session_sender_key_fingerprint.clone(),
        subject_revocation_epoch: value.revocation_epochs.subject,
        service_revocation_epoch: value.revocation_epochs.service,
        device_revocation_epoch: value.revocation_epochs.device,
        session_revocation_epoch: value.revocation_epochs.session,
        device_posture_state: value.device_posture.state.clone(),
        device_posture_revision: value.device_posture.revision,
        device_proof_key_ref: value.device_proof_key_ref.clone(),
        response_config_generation: response_generation,
        response_command_digest: response_digest.into(),
        authority_issued_at_epoch_s: identity.current_status.issued_at_epoch_s,
        updated_at_epoch_s: now,
    }
}
