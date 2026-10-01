use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancelResponseTrustV1,
    decode_endpoint_revocation_execution_cancel_finalize_request_strict,
    validate_endpoint_revocation_execution_cancel_finalize_against_acceptance,
    verify_endpoint_revocation_execution_cancel_response_historic_at,
    verify_endpoint_revocation_execution_cancellation_historic,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1};

pub(super) fn exact(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(request) = value.cancel_finalize_request.as_ref().or_else(|| {
        value
            .cleanup_complete_request
            .as_ref()
            .map(|complete| complete.cancel_finalize_request.as_ref())
    }) else {
        return Ok(());
    };
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancel_finalize_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let central = value
        .execution_cancellation_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    verify_endpoint_revocation_execution_cancellation_historic(
        &decoded.cancellation,
        &decoded.cancellation_request,
        &central.peer_device_ref,
        &crate::cancel_central_trust::cancellation_historic(central),
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    validate_endpoint_revocation_execution_cancel_finalize_against_acceptance(
        &decoded,
        &decoded.cancellation,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    let trust = crate::cancel_response_trust::begin(value)?;
    verify_endpoint_revocation_execution_cancel_response_historic_at(
        &decoded,
        &decoded.cancellation,
        &EndpointRevocationExecutionCancelResponseTrustV1 {
            key_id: trust.key_id,
            public_key_hex: trust.public_key_hex,
            minimum_config_generation: trust.minimum_config_generation,
            now_epoch_s: value.updated_at_epoch_s,
        },
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = decoded == *request
        && value.central_envelope.as_deref()
            == Some(&decoded.cancellation_request.cancel_envelope)
        && decoded.operation_id == value.operation_id;
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
