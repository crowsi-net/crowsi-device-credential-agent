use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    independent_approve_state_types::IndependentApproveResume, replay::DurableSecurityState,
};

pub(crate) fn load_or_reserve<I: IdentityEvidenceProvider>(
    _config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    if let Some(value) = crate::independent_approve_state::load(state, browser)? {
        return unexpired(value, now);
    }
    let finish = identity.prepare_finish_fresh_uv(&browser.command)?;
    let value = crate::independent_approve_state_reserve::reserve(state, browser, &finish, now)?;
    unexpired(value, now)
}

pub(crate) fn unexpired(
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let resumable =
        crate::independent_approve_state::phase_can_resume_expired(value.approval.phase);
    if now >= value.approval.expires_at_epoch_s && !resumable {
        Err(AgentError::FreshUserVerificationRequired)
    } else {
        Ok(value)
    }
}
