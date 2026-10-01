use ihat_identity_assertion_contracts::{
    AssertionVerifier, IdentityEvidenceMetadata, current_status_matches_assertion,
    verify_assertion_at, verify_current_status_at,
};

use crate::{
    AgentError, config::AgentConfigDocument, crypto, identity_locator::IdentitySessionLocatorV1,
};

pub(crate) fn identity(
    config: &AgentConfigDocument,
    locator: &IdentitySessionLocatorV1,
    value: &IdentityEvidenceMetadata,
    nonce: &str,
    now: u64,
) -> Result<(), AgentError> {
    verify_assertion_at(
        &value.assertion,
        &Pinned {
            id: &config.identity_key_id,
            public: &config.identity_public_key_hex,
        },
        &config.identity_issuer,
        &config.identity_audience,
        now,
    )
    .map_err(|_| AgentError::IdentityAssertionInvalid)?;
    verify_current_status_at(
        &value.current_status,
        &Pinned {
            id: &config.current_status_key_id,
            public: &config.current_status_public_key_hex,
        },
        &config.identity_issuer,
        &config.identity_audience,
        now,
    )
    .map_err(|_| AgentError::CurrentStatusInvalid)?;
    let assertion = &value.assertion;
    let trust = &config.management_projection_trust;
    let exact = current_status_matches_assertion(&value.current_status, assertion)
        && assertion.service_id == locator.service_id
        && assertion.pairwise_subject == locator.pairwise_subject
        && assertion.device_id == locator.device_id
        && assertion.session_ref == locator.session_ref
        && assertion.nonce == nonce
        && assertion.device_proof_key_ref == trust.device_proof_key_ref
        && assertion.device_posture.state == trust.device_posture_state
        && assertion.device_posture.revision >= trust.minimum_device_posture_revision
        && assertion.revocation_epochs.subject >= trust.minimum_subject_revocation_epoch
        && assertion.revocation_epochs.service >= trust.minimum_service_revocation_epoch
        && assertion.revocation_epochs.device >= trust.minimum_device_revocation_epoch
        && assertion.revocation_epochs.session >= trust.minimum_session_revocation_epoch;
    exact
        .then_some(())
        .ok_or(AgentError::IdentityAssertionInvalid)
}

struct Pinned<'a> {
    id: &'a str,
    public: &'a str,
}

impl AssertionVerifier for Pinned<'_> {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        key_id == self.id && crypto::verify_hex(self.public, signature, payload)
    }
}
