use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupPhaseV1, ManagementCommandV2, ManagementRequestV2,
};

use crate::{
    AgentError, VerifiedConfig, actor_options_state_types::ActorOptionsResume,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
};

pub(crate) fn load_or_reserve<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    if let Some(value) = crate::actor_options_state_reserve::load(state, browser)? {
        return unexpired(value, now);
    }
    let current = identity.prepare_current_identity(&config.0, now)?;
    let value = crate::actor_options_state_reserve::reserve(state, browser, &current, now)?;
    unexpired(value, now)
}

pub(crate) fn phase(
    browser: &ManagementRequestV2,
) -> Result<EndpointPreparedLookupPhaseV1, AgentError> {
    match browser.command {
        ManagementCommandV2::TargetOptions { .. } => Ok(EndpointPreparedLookupPhaseV1::Target),
        ManagementCommandV2::ApprovalOptions { .. } => Ok(EndpointPreparedLookupPhaseV1::Approval),
        _ => Err(AgentError::RequestInvalid),
    }
}

pub(crate) fn unexpired(
    value: ActorOptionsResume,
    now: u64,
) -> Result<ActorOptionsResume, AgentError> {
    let historic = matches!(
        value.journal.phase,
        crate::actor_options_state_types::ActorOptionsPhaseV1::CentralInvoking
            | crate::actor_options_state_types::ActorOptionsPhaseV1::Unknown
            | crate::actor_options_state_types::ActorOptionsPhaseV1::Complete
    ) && value
        .fresh
        .as_ref()
        .map(|value| crate::fresh_uv_options::expires_at(value))
        .transpose()?
        .flatten()
        .is_some_and(|expires| now < expires);
    if now < value.journal.expires_at_epoch_s || historic {
        Ok(value)
    } else {
        Err(AgentError::FreshUserVerificationRequired)
    }
}
