use crowsi_credential_authority_contracts::{
    EndpointRevocationCancellationCleanupResponseTrustV1,
    decode_endpoint_revocation_execution_cancellation_cleanup_strict,
    verify_endpoint_revocation_cancellation_cleanup_exchange_historic_at,
    verify_endpoint_revocation_execution_cancellation_cleanup_historic,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1};

pub(super) fn exact(value: &CancelRecordV1) -> Result<(), AgentError> {
    let complete = value.cleanup_complete_request.as_ref();
    let cleanup = value
        .cancellation_cleanup
        .as_ref()
        .or_else(|| complete.map(|item| item.cleanup.as_ref()));
    let finalize = value
        .cancel_finalize_request
        .as_ref()
        .or_else(|| complete.map(|item| item.cancel_finalize_request.as_ref()));
    let acknowledge = if value.cancellation_cleanup.is_some() {
        value.cleanup_ack_exchange.as_ref()
    } else {
        value
            .cleanup_ack_exchange
            .as_ref()
            .or_else(|| complete.map(|item| &item.acknowledge_exchange))
    };
    let Some(cleanup) = cleanup else {
        return acknowledge
            .is_none()
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    let finalize = finalize.ok_or(AgentError::AuthorityRollback)?;
    let wire = serde_json::to_vec(cleanup).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancellation_cleanup_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let pin = value
        .cancellation_cleanup_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    verify_endpoint_revocation_execution_cancellation_cleanup_historic(
        &decoded,
        finalize,
        &finalize.cancellation,
        &pin.peer_device_ref,
        &crate::cancel_central_trust::cleanup_historic(pin),
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    if decoded != *cleanup {
        return Err(AgentError::AuthorityRollback);
    }
    acknowledgement(value, cleanup, acknowledge)
}

fn acknowledgement(
    value: &CancelRecordV1,
    cleanup: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupV1,
    exchange: Option<&crowsi_credential_authority_contracts::SignedAuthorityExchangeV1>,
) -> Result<(), AgentError> {
    let Some(exchange) = exchange else {
        return value
            .cleanup_response_trust
            .is_none()
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    };
    let pin = value
        .cleanup_response_trust
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    verify_endpoint_revocation_cancellation_cleanup_exchange_historic_at(
        exchange,
        cleanup,
        &EndpointRevocationCancellationCleanupResponseTrustV1 {
            key_id: &pin.key_id,
            public_key_hex: &pin.public_key_hex,
            minimum_config_generation: pin.minimum_config_generation,
            now_epoch_s: value.updated_at_epoch_s,
        },
    )
    .map_err(|_| AgentError::AuthorityRollback)
}
