use crowsi_credential_authority_contracts::{ManagementRequestV2, identity_evidence_from_exchange};
use ihat_identity_assertion_contracts::decode_authority_request_strict;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, source_options_state::SourceOptionsResume,
};

pub(crate) fn load_or_reserve<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity_provider: &I,
    browser: &ManagementRequestV2,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    if let Some(value) = crate::source_options_state_reserve::load(state, browser)? {
        return unexpired(value, now);
    }
    let identity_exchange = identity_provider.current_identity(&config.0, now)?;
    crate::core_identity::verify_and_observe(config, state, &identity_exchange, now)?;
    let identity = identity_evidence_from_exchange(&identity_exchange)
        .map_err(|_| AgentError::IdentityUnavailable)?;
    let cached = state.management_snapshot(now)?;
    let prepared = crate::prepared_operation::build(browser, identity, &cached, &config.0, now)?;
    let (expected_kind, expected_scope) =
        crate::source_options_scope::expected(&prepared, &cached.snapshot)?;
    let begin =
        identity_provider.prepare_begin_fresh_uv(&config.0, &identity_exchange, &prepared, now)?;
    let wire = serde_json::to_vec(&begin).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
    if decoded != begin || !begin.evidence.is_empty() {
        return Err(AgentError::RequestInvalid);
    }
    let value = crate::source_options_state_reserve::reserve(
        state,
        browser,
        &prepared,
        &expected_kind,
        &expected_scope,
        &identity_exchange,
        &begin,
        now,
    )?;
    unexpired(value, now)
}

pub(crate) fn unexpired(
    value: SourceOptionsResume,
    now: u64,
) -> Result<SourceOptionsResume, AgentError> {
    let historic = matches!(
        value.journal.phase,
        crate::source_options_state::SourceOptionsPhaseV1::CentralInvoking
            | crate::source_options_state::SourceOptionsPhaseV1::Unknown
            | crate::source_options_state::SourceOptionsPhaseV1::Complete
    ) && crate::fresh_uv_options::expires_at(&value.fresh_uv)?
        .is_some_and(|expires| now < expires);
    if now < value.journal.expires_at_epoch_s || historic {
        Ok(value)
    } else {
        Err(AgentError::FreshUserVerificationRequired)
    }
}
