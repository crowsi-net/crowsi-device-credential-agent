use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointFreshUvTrustV2, EndpointIdentityTrustV2,
    verify_endpoint_approval_at,
};

use crate::{
    AgentError, config::AgentConfigDocument,
    independent_approve_state_types::IndependentApproveResume,
};

pub(crate) fn actor(
    config: &AgentConfigDocument,
    value: &IndependentApproveResume,
    now: u64,
) -> Result<(), AgentError> {
    let finish = value
        .approval
        .finish_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let current = value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    verify_endpoint_approval_at(
        &value.selected_identity,
        &value.selected_begin,
        finish,
        current,
        &value.lookup.response.prepared,
        &value.approval.browser_request.command,
        &EndpointAuthorityResponseTrustV2 {
            minimum_config_generation: config.minimum_identity_config_generation,
            key_id: &config.authority_response_key_id,
            public_key_hex: &config.authority_response_public_key_hex,
        },
        &EndpointIdentityTrustV2 {
            issuer: &config.identity_issuer,
            audience: &config.identity_audience,
            assertion_key_id: &config.identity_key_id,
            assertion_public_key_hex: &config.identity_public_key_hex,
            current_status_key_id: &config.current_status_key_id,
            current_status_public_key_hex: &config.current_status_public_key_hex,
            now_epoch_s: now,
        },
        &EndpointFreshUvTrustV2 {
            account_binding_sha256: &config.user_verification_account_binding_sha256,
            key_id: &config.user_verification_key_id,
            public_key_hex: &config.user_verification_public_key_hex,
            now_epoch_s: now,
        },
    )
    .map(|_| ())
    .map_err(|_| AgentError::AuthorityResponseInvalid)
}
