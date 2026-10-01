use crowsi_credential_authority_contracts::ManagementRequestV2;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, target_approve_state_types::TargetApproveResume,
};

pub(crate) fn load_or_reserve<I: IdentityEvidenceProvider>(
    _config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    if let Some(value) = crate::target_approve_state::load(state, browser)? {
        return unexpired(value, now);
    }
    let finish = identity.prepare_finish_fresh_uv(&browser.command)?;
    let value = crate::target_approve_state_reserve::reserve(state, browser, &finish, now)?;
    unexpired(value, now)
}

pub(crate) fn unexpired(
    value: TargetApproveResume,
    now: u64,
) -> Result<TargetApproveResume, AgentError> {
    if now >= value.approval.expires_at_epoch_s
        && !crate::target_approve_state::can_resume_expired(&value.approval)
    {
        Err(AgentError::FreshUserVerificationRequired)
    } else {
        Ok(value)
    }
}
