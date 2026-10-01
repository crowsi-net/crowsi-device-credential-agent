use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelRecordV1,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
};

pub(crate) fn load_or_reserve<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    if let Some(value) = crate::cancel_state_reserve::load(state, browser, now)? {
        return unexpired(value, now);
    }
    let current = identity.prepare_current_identity(&config.0, now)?;
    let value = crate::cancel_state_reserve::reserve(state, browser, &current, now)?;
    unexpired(value, now)
}

pub(crate) fn unexpired(value: Box<CancelRecordV1>, now: u64) -> Result<Box<CancelRecordV1>, AgentError> {
    let live = now < value.expires_at_epoch_s;
    if live
        || value.phase == crate::cancel_state_types::CancelPhaseV1::Complete
        || crate::cancel_state::can_resume_expired(&value)
    {
        Ok(value)
    } else {
        Err(AgentError::IdentityUnavailable)
    }
}
