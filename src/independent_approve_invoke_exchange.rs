use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, SignedAuthorityExchangeV1, verify_authority_exchange_at,
    verify_authority_exchange_historic,
};
use ihat_identity_assertion_contracts::{
    AuthorityRequestV1, decode_authority_request_strict, decode_authority_response_strict,
};

use crate::{AgentError, transport::AuthorityTransport};

#[allow(clippy::too_many_arguments)]
pub(super) fn invoke<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    request: &AuthorityRequestV1,
    wire: &str,
    expected: &str,
    historic: bool,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let decoded =
        decode_authority_request_strict(wire.as_bytes()).map_err(|_| AgentError::RequestInvalid)?;
    if decoded != *request {
        return Err(AgentError::OperationReplay);
    }
    let response = transport.exchange("ihat_authority_v1", wire.as_bytes(), now)?;
    let response = decode_authority_response_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let exchange = SignedAuthorityExchangeV1 {
        request: decoded,
        response,
    };
    if historic {
        verify_authority_exchange_historic(
            &exchange,
            expected,
            trust.minimum_config_generation,
            trust.key_id,
            trust.public_key_hex,
        )
    } else {
        verify_authority_exchange_at(
            &exchange,
            expected,
            trust.minimum_config_generation,
            trust.key_id,
            trust.public_key_hex,
            now,
        )
    }
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    Ok(exchange)
}

pub(super) fn pinned(
    exchange: &SignedAuthorityExchangeV1,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    expected: &str,
) -> Result<(), AgentError> {
    verify_authority_exchange_historic(
        exchange,
        expected,
        trust.minimum_config_generation,
        trust.key_id,
        trust.public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)
}
