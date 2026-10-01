use crowsi_credential_authority_contracts::{
    ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA,
    EndpointRevocationExecutionCancelFinalizeRequestV1,
    decode_endpoint_revocation_execution_cancel_finalize_request_strict,
    validate_endpoint_revocation_execution_cancel_finalize_against_acceptance,
    verify_endpoint_revocation_execution_cancel_response_historic_at,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1, random_id};

pub(super) fn build(
    value: &CancelRecordV1,
    exchange: &crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    now: u64,
) -> Result<EndpointRevocationExecutionCancelFinalizeRequestV1, AgentError> {
    let cancellation_request = value
        .execution_cancel_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let cancellation = value
        .execution_cancellation
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = EndpointRevocationExecutionCancelFinalizeRequestV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCEL_FINALIZE_REQUEST_SCHEMA.into(),
        request_id: random_id::create("revocation-execution-cancel-finalize")?,
        operation_id: value.operation_id.clone(),
        cancellation_request: cancellation_request.clone(),
        cancellation: Box::new(cancellation.clone()),
        cancel_pending_exchange: exchange.clone(),
    };
    let wire = serde_json::to_vec(&request).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_revocation_execution_cancel_finalize_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    validate_endpoint_revocation_execution_cancel_finalize_against_acceptance(
        &decoded,
        cancellation,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let trust = crate::cancel_response_trust::begin(value)?;
    verify_endpoint_revocation_execution_cancel_response_historic_at(
        &decoded,
        cancellation,
        &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancelResponseTrustV1 {
            key_id: trust.key_id,
            public_key_hex: trust.public_key_hex,
            minimum_config_generation: trust.minimum_config_generation,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    Ok(decoded)
}
