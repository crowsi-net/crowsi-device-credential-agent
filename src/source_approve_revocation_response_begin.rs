use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1, validate_authority_exchange,
};
use ihat_identity_assertion_contracts::{
    AuthorityEvidence, AuthorityResult, FreshUvV1, ResponseOutcome, RevocationCeremonyMetadata,
    RevocationCeremonyStateDto,
};

use crate::AgentError;

pub(crate) fn validate(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    crate::source_approve_revocation_request::validate_begin(
        prepared,
        fresh,
        &exchange.request,
        now,
    )?;
    current(prepared, exchange, now)
}

pub(crate) fn current(
    prepared: &EndpointPreparedOperationV2,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    let ceremony_expires = metadata(prepared, exchange)?.expires_at_epoch_s;
    (prepared.issued_at_epoch_s <= now
        && now < prepared.expires_at_epoch_s
        && now < ceremony_expires)
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}

pub(crate) fn metadata<'a>(
    prepared: &EndpointPreparedOperationV2,
    exchange: &'a SignedAuthorityExchangeV1,
) -> Result<&'a RevocationCeremonyMetadata, AgentError> {
    let fresh = match exchange.request.evidence.as_slice() {
        [
            AuthorityEvidence::FreshUv(value),
            AuthorityEvidence::Signed(_),
        ] => value,
        _ => return Err(AgentError::AuthorityResponseInvalid),
    };
    crate::source_approve_revocation_request::validate_begin(
        prepared,
        fresh,
        &exchange.request,
        exchange.response.issued_at_epoch_s,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    validate_authority_exchange(exchange, exchange.request.command.type_name())
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(value),
    } = &exchange.response.outcome
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    response_shape(prepared, exchange, value)?;
    Ok(value)
}

fn response_shape(
    prepared: &EndpointPreparedOperationV2,
    exchange: &SignedAuthorityExchangeV1,
    value: &RevocationCeremonyMetadata,
) -> Result<(), AgentError> {
    let requirements = crate::source_approve_revocation_binding::requirements(prepared)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let independent = requirements.target_device_ref != prepared.source_device_ref;
    let state = if independent {
        RevocationCeremonyStateDto::AwaitingIndependentApproval
    } else {
        RevocationCeremonyStateDto::ReadyToFinalize
    };
    let approval = if independent {
        value.approval_nonce.as_deref().is_some_and(bounded)
            && requirements
                .required_approval_authority_ref
                .as_deref()
                .is_some_and(bounded)
    } else {
        value.approval_nonce.is_none() && requirements.required_approval_authority_ref.is_none()
    };
    let lifetime = value
        .expires_at_epoch_s
        .checked_sub(exchange.response.issued_at_epoch_s);
    let exact = value.finalize_command_id == prepared.operation_id
        && value.independent_approval_required == independent
        && value.state == state
        && bounded(&value.attempt_id)
        && lower_hex_32(&value.target_digest)
        && lifetime.is_some_and(|seconds| (1..=300).contains(&seconds))
        && approval;
    exact
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
}

fn lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
