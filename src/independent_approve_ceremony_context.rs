use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;

use crate::{AgentError, independent_approve_state_types::IndependentApproveResume};

pub(super) fn begun(
    value: &IndependentApproveResume,
) -> Result<&SignedAuthorityExchangeV1, AgentError> {
    value
        .lookup
        .response
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn current(
    value: &IndependentApproveResume,
) -> Result<&SignedAuthorityExchangeV1, AgentError> {
    value
        .approval
        .current_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn approval_pin(value: &IndependentApproveResume) -> Result<(&str, &str), AgentError> {
    Ok((
        value
            .approval
            .approval_key_id
            .as_deref()
            .ok_or(AgentError::AuthorityRollback)?,
        value
            .approval
            .approval_public_key_hex
            .as_deref()
            .ok_or(AgentError::AuthorityRollback)?,
    ))
}
