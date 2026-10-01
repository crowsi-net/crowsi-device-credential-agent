use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, SignedAuthorityExchangeV1, verify_authority_exchange_at,
    verify_authority_exchange_historic,
};
use ihat_identity_assertion_contracts::{
    AuthorityRequestV1, decode_authority_request_strict, decode_authority_response_strict,
};

use crate::{AgentError, transport::AuthorityTransport};

pub(super) fn historic<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    request: &AuthorityRequestV1,
    expected: &str,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    exchange(transport, trust, request, expected, true, now)
}

pub(super) fn fresh<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    request: &AuthorityRequestV1,
    expected: &str,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    exchange(transport, trust, request, expected, false, now)
}

fn exchange<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    request: &AuthorityRequestV1,
    expected: &str,
    historic: bool,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
    if decoded != *request {
        return Err(AgentError::RequestInvalid);
    }
    let response = transport.exchange("ihat_authority_v1", &wire, now)?;
    let response = decode_authority_response_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let value = SignedAuthorityExchangeV1 {
        request: decoded,
        response,
    };
    if historic {
        verify_authority_exchange_historic(
            &value,
            expected,
            trust.minimum_config_generation,
            trust.key_id,
            trust.public_key_hex,
        )
    } else {
        verify_authority_exchange_at(
            &value,
            expected,
            trust.minimum_config_generation,
            trust.key_id,
            trust.public_key_hex,
            now,
        )
    }
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    Ok(value)
}
