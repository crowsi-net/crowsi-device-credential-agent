use crowsi_credential_authority_contracts::{
    SignedAuthorityExchangeV1, identity_evidence_from_exchange, verify_authority_exchange_at,
};
use ihat_identity_assertion_contracts::{AuthorityCommand, command_digest};

use crate::{AgentError, VerifiedConfig, replay::DurableSecurityState};

pub(crate) fn verify(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    let value = &config.0;
    verify_authority_exchange_at(
        exchange,
        "issue_current_device_identity_evidence",
        value.minimum_identity_config_generation,
        &value.authority_response_key_id,
        &value.authority_response_public_key_hex,
        now,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &exchange.request.command
    else {
        return Err(AgentError::IdentityUnavailable);
    };
    let identity =
        identity_evidence_from_exchange(exchange).map_err(|_| AgentError::IdentityUnavailable)?;
    let store = state.identity_locator();
    let locator = store.load(value)?;
    crate::identity_verify::identity(value, &locator, identity, &command.identity_nonce, now)?;
    command_digest(&exchange.request).map_err(|_| AgentError::RequestInvalid)?;
    Ok(())
}

pub(super) fn verify_and_observe(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    verify(config, state, exchange, now)?;
    let value = &config.0;
    let identity =
        identity_evidence_from_exchange(exchange).map_err(|_| AgentError::IdentityUnavailable)?;
    let store = state.identity_locator();
    let locator = store.load(value)?;
    if crate::identity_locator_validation::same_identity(&locator, identity) {
        return Ok(());
    }
    let digest = command_digest(&exchange.request).map_err(|_| AgentError::RequestInvalid)?;
    store.observe_current_evidence(
        value,
        &locator,
        identity,
        exchange.response.config_generation,
        &digest,
        now,
    )?;
    Ok(())
}
