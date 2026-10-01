use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupPhaseV1, EndpointPreparedLookupRequestV1,
    EndpointPreparedLookupResponseV1, verify_authority_exchange_at,
};

use crate::{
    AgentError, actor_options_state_types::PreparedRevocationResponseTrustV1,
    config::AgentConfigDocument,
};

pub(super) fn verify(
    config: &AgentConfigDocument,
    request: &EndpointPreparedLookupRequestV1,
    response: &EndpointPreparedLookupResponseV1,
    now: u64,
) -> Result<Option<PreparedRevocationResponseTrustV1>, AgentError> {
    if request.phase != EndpointPreparedLookupPhaseV1::Approval {
        return response
            .revocation_begin_exchange
            .is_none()
            .then_some(None)
            .ok_or(AgentError::AuthorityResponseInvalid);
    }
    let begun = response
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityResponseInvalid)?;
    verify_authority_exchange_at(
        begun,
        begun.request.command.type_name(),
        config.minimum_identity_config_generation,
        &config.authority_response_key_id,
        &config.authority_response_public_key_hex,
        now,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    Ok(Some(PreparedRevocationResponseTrustV1 {
        key_id: config.authority_response_key_id.clone(),
        public_key_hex: config.authority_response_public_key_hex.clone(),
        minimum_config_generation: begun.response.config_generation,
    }))
}
