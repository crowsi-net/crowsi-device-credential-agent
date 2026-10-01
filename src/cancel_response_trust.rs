use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, SignedAuthorityExchangeV1, verify_authority_exchange_historic,
};

use crate::{
    AgentError, VerifiedConfig,
    cancel_state_types::{CancelRecordV1, CancelResponseTrustPinV1},
};

pub(super) fn begin(
    value: &CancelRecordV1,
) -> Result<EndpointAuthorityResponseTrustV2<'_>, AgentError> {
    let pin = value
        .revocation_response_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let begun = value
        .revocation_begin_exchange
        .as_ref()
        .or_else(|| {
            value
                .execution_cancel_request
                .as_ref()
                .map(|request| &request.begin_exchange)
        })
        .or_else(|| {
            value
                .cancel_finalize_request
                .as_ref()
                .map(|request| &request.cancellation_request.begin_exchange)
        })
        .or_else(|| {
            value.cleanup_complete_request.as_ref().map(|request| {
                &request
                    .cancel_finalize_request
                    .cancellation_request
                    .begin_exchange
            })
        })
        .ok_or(AgentError::AuthorityRollback)?;
    if begun.response.key_id != pin.key_id
        || begun.response.config_generation != pin.minimum_config_generation
    {
        return Err(AgentError::AuthorityRollback);
    }
    verify_authority_exchange_historic(
        begun,
        begun.request.command.type_name(),
        pin.minimum_config_generation,
        &pin.key_id,
        &pin.public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    Ok(trust(pin))
}

pub(super) fn accepted(
    config: &VerifiedConfig,
    value: &SignedAuthorityExchangeV1,
) -> Result<CancelResponseTrustPinV1, AgentError> {
    let exact = value.response.key_id == config.0.authority_response_key_id
        && value.response.config_generation >= config.0.minimum_identity_config_generation;
    exact
        .then_some(CancelResponseTrustPinV1 {
            key_id: config.0.authority_response_key_id.clone(),
            public_key_hex: config.0.authority_response_public_key_hex.clone(),
            minimum_config_generation: value.response.config_generation,
        })
        .ok_or(AgentError::AuthorityResponseInvalid)
}

pub(super) fn trust(pin: &CancelResponseTrustPinV1) -> EndpointAuthorityResponseTrustV2<'_> {
    EndpointAuthorityResponseTrustV2 {
        minimum_config_generation: pin.minimum_config_generation,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
    }
}
