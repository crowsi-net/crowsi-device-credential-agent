use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, SignedAuthorityExchangeV1, verify_authority_exchange_historic,
};

use crate::{AgentError, source_approve_state_types::SourceApproveRecordV1};

pub(crate) fn set(
    value: &mut SourceApproveRecordV1,
    begun: &SignedAuthorityExchangeV1,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
) -> Result<(), AgentError> {
    verify_authority_exchange_historic(
        begun,
        begun.request.command.type_name(),
        trust.minimum_config_generation,
        trust.key_id,
        trust.public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    value.revocation_response_key_id = Some(trust.key_id.into());
    value.revocation_response_public_key_hex = Some(trust.public_key_hex.into());
    value.revocation_response_minimum_generation = Some(begun.response.config_generation);
    Ok(())
}

pub(crate) fn trust(
    value: &SourceApproveRecordV1,
) -> Result<EndpointAuthorityResponseTrustV2<'_>, AgentError> {
    let key_id = value
        .revocation_response_key_id
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?;
    let public_key_hex = value
        .revocation_response_public_key_hex
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?;
    let minimum_config_generation = value
        .revocation_response_minimum_generation
        .ok_or(AgentError::AuthorityRollback)?;
    Ok(EndpointAuthorityResponseTrustV2 {
        minimum_config_generation,
        key_id,
        public_key_hex,
    })
}

pub(crate) fn validate(
    value: &SourceApproveRecordV1,
    begun: &SignedAuthorityExchangeV1,
) -> Result<(), AgentError> {
    let trust = trust(value)?;
    let exact = trust.minimum_config_generation == begun.response.config_generation
        && trust.key_id == begun.response.key_id;
    if !exact {
        return Err(AgentError::AuthorityRollback);
    }
    verify_authority_exchange_historic(
        begun,
        begun.request.command.type_name(),
        trust.minimum_config_generation,
        trust.key_id,
        trust.public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)
}

pub(crate) fn empty(value: &SourceApproveRecordV1) -> bool {
    value.revocation_response_key_id.is_none()
        && value.revocation_response_public_key_hex.is_none()
        && value.revocation_response_minimum_generation.is_none()
}
