use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointPreparedOperationV2, ManagementIntentV2,
    SignedAuthorityExchangeV1, verify_authority_exchange_at,
};
use ihat_identity_assertion_contracts::{
    AuthorityRequestV1, FreshUvV1, decode_authority_request_strict,
    decode_authority_response_strict,
};

use crate::{AgentError, config::AgentConfigDocument, transport::AuthorityTransport};

pub(crate) fn begin<T: AuthorityTransport>(
    transport: &T,
    config: &AgentConfigDocument,
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    begin_with_trust(transport, &trust(config), prepared, fresh, request, now)
}

pub(crate) fn begin_with_trust<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crate::source_approve_revocation_request::validate_begin(prepared, fresh, request, now)?;
    let exchange = exchange(transport, trust, request, begin_name(prepared)?, false, now)?;
    crate::source_approve_revocation_response_begin::validate(prepared, fresh, &exchange, now)?;
    Ok(exchange)
}

#[cfg(test)]
pub(crate) fn finalize_with_trust<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
    historic_recovery: bool,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crate::source_approve_revocation_final_request::validate(prepared, begun, request)?;
    if !historic_recovery {
        crate::source_approve_revocation_response_begin::current(prepared, begun, now)?;
    }
    let exchange = exchange(
        transport,
        trust,
        request,
        final_name(prepared)?,
        historic_recovery,
        now,
    )?;
    crate::source_approve_revocation_response_final::validate_unreserved_for_test(
        prepared, begun, &exchange, now,
    )?;
    Ok(exchange)
}

include!("source_approve_revocation_invoke_reserved.rs");

fn exchange<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    request: &AuthorityRequestV1,
    expected: &str,
    historic_recovery: bool,
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
    let exchange = SignedAuthorityExchangeV1 {
        request: decoded,
        response,
    };
    if historic_recovery {
        crowsi_credential_authority_contracts::verify_authority_exchange_historic(
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

pub(crate) fn trust(value: &AgentConfigDocument) -> EndpointAuthorityResponseTrustV2<'_> {
    EndpointAuthorityResponseTrustV2 {
        minimum_config_generation: value.minimum_identity_config_generation,
        key_id: &value.authority_response_key_id,
        public_key_hex: &value.authority_response_public_key_hex,
    }
}

fn begin_name(value: &EndpointPreparedOperationV2) -> Result<&'static str, AgentError> {
    match &value.intent {
        ManagementIntentV2::DeviceRevocation { .. } => Ok("begin_device_revocation"),
        ManagementIntentV2::SessionRevocation { .. } => Ok("begin_session_revocation"),
        ManagementIntentV2::DeviceTransfer { .. } => Err(AgentError::RequestInvalid),
    }
}

fn final_name(value: &EndpointPreparedOperationV2) -> Result<&'static str, AgentError> {
    match &value.intent {
        ManagementIntentV2::DeviceRevocation { .. } => Ok("revoke_device_by_ref"),
        ManagementIntentV2::SessionRevocation { .. } => Ok("revoke_session_by_ref"),
        ManagementIntentV2::DeviceTransfer { .. } => Err(AgentError::RequestInvalid),
    }
}
