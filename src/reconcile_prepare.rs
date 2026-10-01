use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig,
    identity_provider::IdentityEvidenceProvider,
    reconcile_state_types::{ReconcilePhaseV1, ReconcileRecordV1},
    replay::DurableSecurityState,
};

pub(crate) fn load_or_reserve<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    if let Some(value) = crate::reconcile_state_reserve::load(state, browser, now)? {
        return unexpired(value, now);
    }
    let current = identity.prepare_current_identity(&config.0, now)?;
    let value = crate::reconcile_state_reserve::reserve(state, browser, &current, now)?;
    unexpired(value, now)
}

pub(crate) fn unexpired(
    value: ReconcileRecordV1,
    now: u64,
) -> Result<ReconcileRecordV1, AgentError> {
    let historic = crate::reconcile_state::central_ambiguous(&value)
        || value.phase == ReconcilePhaseV1::Complete;
    if now < value.expires_at_epoch_s || historic {
        Ok(value)
    } else {
        Err(AgentError::IdentityUnavailable)
    }
}
