use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1, validate_authority_exchange,
};
use ihat_identity_assertion_contracts::{
    AuthorityResult, ResponseOutcome, RevocationCeremonyStateDto,
};

use crate::AgentError;

pub(crate) fn validate(
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    exchange: &SignedAuthorityExchangeV1,
) -> Result<(), AgentError> {
    crate::independent_approve_request_validation::historic(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        &exchange.request,
    )?;
    validate_authority_exchange(exchange, "approve_revocation")
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let metadata = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?;
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationApproved(approval),
    } = &exchange.response.outcome
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let exact = approval.attempt_id == metadata.attempt_id
        && approval.finalize_command_id == prepared.operation_id
        && approval.approval_count == 1
        && approval.ready_to_finalize
        && approval.state == RevocationCeremonyStateDto::ReadyToFinalize
        && exchange.response.key_id == begun.response.key_id
        && exchange.response.config_generation >= begun.response.config_generation
        && exchange.response.issued_at_epoch_s >= begun.response.issued_at_epoch_s
        && exchange.response.issued_at_epoch_s < metadata.expires_at_epoch_s;
    exact
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}
