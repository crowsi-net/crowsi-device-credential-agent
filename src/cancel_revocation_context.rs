use crowsi_credential_authority_contracts::{
    EndpointPreparedLookupResponseV1, ManagementOperationState, SignedAuthorityExchangeV1,
    verify_authority_exchange_historic,
};

use crate::{
    AgentError,
    cancel_state_types::CancelResponseTrustPinV1,
    source_options_state_types::{OperationJournalV1, PreparedOperationsV1},
};

pub(super) struct CancelRevocationContextV1 {
    pub begin: SignedAuthorityExchangeV1,
    pub response_trust: CancelResponseTrustPinV1,
    pub pre_final_digest: String,
}

pub(super) fn load(
    prepared: &PreparedOperationsV1,
    journal: &OperationJournalV1,
    lookup: &EndpointPreparedLookupResponseV1,
) -> Result<Option<CancelRevocationContextV1>, AgentError> {
    if lookup.operation.state != ManagementOperationState::AwaitingRevocationFinal {
        return lookup
            .pre_final_acceptance_request_sha256
            .is_none()
            .then_some(None)
            .ok_or(AgentError::AuthorityRollback);
    }
    let source = prepared
        .records
        .get(&lookup.operation.operation_id)
        .ok_or(AgentError::AuthorityRollback)?;
    let approval = journal
        .source_approvals
        .get(&lookup.operation.operation_id)
        .ok_or(AgentError::AuthorityRollback)?;
    let begin = approval
        .revocation_begin_exchange
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let key_id = approval
        .revocation_response_key_id
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let public_key_hex = approval
        .revocation_response_public_key_hex
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let generation = approval
        .revocation_response_minimum_generation
        .ok_or(AgentError::AuthorityRollback)?;
    let exact = source.prepared == lookup.prepared
        && approval.execution_reservation.is_none()
        && begin.response.key_id == *key_id
        && begin.response.config_generation == generation;
    if !exact {
        return Err(AgentError::AuthorityRollback);
    }
    crate::source_approve_revocation_response_begin::metadata(&lookup.prepared, begin)
        .map_err(|_| AgentError::AuthorityRollback)?;
    verify_authority_exchange_historic(
        begin,
        begin.request.command.type_name(),
        generation,
        key_id,
        public_key_hex,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    Ok(Some(CancelRevocationContextV1 {
        begin: begin.clone(),
        response_trust: CancelResponseTrustPinV1 {
            key_id: key_id.clone(),
            public_key_hex: public_key_hex.clone(),
            minimum_config_generation: generation,
        },
        pre_final_digest: lookup
            .pre_final_acceptance_request_sha256
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
    }))
}
