use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, SignedAuthorityExchangeV1, verify_authority_exchange_historic,
};

use crate::{AgentError, independent_approve_state_types::IndependentApproveRecordV1};

pub(super) fn current<'a>(
    record: &'a IndependentApproveRecordV1,
    begun: &SignedAuthorityExchangeV1,
) -> Result<EndpointAuthorityResponseTrustV2<'a>, AgentError> {
    let exact = record.response_key_id == begun.response.key_id
        && record.response_minimum_generation == begun.response.config_generation;
    if !exact {
        return Err(AgentError::AuthorityRollback);
    }
    verify_authority_exchange_historic(
        begun,
        begun.request.command.type_name(),
        record.response_minimum_generation,
        &record.response_key_id,
        &record.response_public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    Ok(EndpointAuthorityResponseTrustV2 {
        minimum_config_generation: record.response_minimum_generation,
        key_id: &record.response_key_id,
        public_key_hex: &record.response_public_key_hex,
    })
}
