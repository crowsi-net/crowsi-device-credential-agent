use crowsi_credential_authority_contracts::{
    EndpointRevocationCancellationCleanupResponseTrustV1,
    verify_endpoint_revocation_cancellation_cleanup_exchange_historic_at,
};

use crate::{
    AgentError, VerifiedConfig, cancel_state_types::CancelRecordV1,
    identity_provider::IdentityEvidenceProvider, replay::DurableSecurityState,
};

pub(super) fn invoke<I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    identity: &I,
    value: Box<CancelRecordV1>,
    now: u64,
) -> Result<Box<CancelRecordV1>, AgentError> {
    let operation = value.operation_id.clone();
    let cleanup = value
        .cancellation_cleanup
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let request = crowsi_credential_authority_contracts::attach_revocation_cancellation_cleanup(
        &cleanup.acknowledge_request,
        cleanup,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    crate::cancel_state_phase::cleanup_ack_invoking(state, &operation, now)?;
    let exchange = match identity.invoke_pending_cancellation_ack(&config.0, &request, now) {
        Ok(exchange) => exchange,
        Err(error) => {
            crate::cancel_state_phase::cleanup_ack_unknown(state, &operation, now)?;
            return Err(error);
        }
    };
    crate::cancel_state_phase::cleanup_ack_unknown(state, &operation, now)?;
    let pin = crate::cancel_response_trust::accepted(config, &exchange)?;
    verify_endpoint_revocation_cancellation_cleanup_exchange_historic_at(
        &exchange,
        cleanup,
        &EndpointRevocationCancellationCleanupResponseTrustV1 {
            key_id: &pin.key_id,
            public_key_hex: &pin.public_key_hex,
            minimum_config_generation: pin.minimum_config_generation,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let complete = crate::cancel_cleanup_complete_request::build(&value, &exchange)?;
    crate::cancel_state_ack_accept::persist(state, &operation, &exchange, &complete, pin, now)
}
