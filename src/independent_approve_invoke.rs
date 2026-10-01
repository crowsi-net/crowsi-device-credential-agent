use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointPreparedOperationV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;

use crate::{AgentError, transport::AuthorityTransport};

#[allow(clippy::too_many_arguments)]
pub(crate) fn approval<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
    wire: &str,
    historic: bool,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crate::independent_approve_invoke_exchange::pinned(
        begun,
        trust,
        begun.request.command.type_name(),
    )?;
    let expires = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?
        .expires_at_epoch_s;
    if now >= expires {
        return Err(AgentError::FreshUserVerificationRequired);
    }
    if historic {
        crate::independent_approve_request_validation::historic(
            approval_key_id,
            approval_public_key_hex,
            prepared,
            begun,
            current,
            request,
        )?;
    } else {
        crate::independent_approve_request_validation::current(
            approval_key_id,
            approval_public_key_hex,
            prepared,
            begun,
            current,
            request,
            now,
        )?;
    }
    let exchange = crate::independent_approve_invoke_exchange::invoke(
        transport,
        trust,
        request,
        wire,
        "approve_revocation",
        historic,
        now,
    )?;
    crate::independent_approve_response_approval::validate(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        &exchange,
    )?;
    Ok(exchange)
}

include!("independent_approve_invoke_reserved.rs");
