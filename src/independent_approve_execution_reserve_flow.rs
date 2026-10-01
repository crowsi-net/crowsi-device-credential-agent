use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionReservationTrustV1, attach_revocation_execution_reservation,
    decode_endpoint_revocation_execution_reservation_strict,
    decode_endpoint_revocation_execution_reserve_request_strict,
    verify_endpoint_revocation_execution_reservation_at,
};

use crate::{
    AgentError, VerifiedConfig,
    independent_approve_state_types::{IndependentApproveResume, IndependentReservationTrustPinV1},
    replay::DurableSecurityState,
    transport::AuthorityTransport,
};

pub(super) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    value: IndependentApproveResume,
    now: u64,
) -> Result<IndependentApproveResume, AgentError> {
    let operation = value.approval.operation_id.clone();
    let invoking =
        crate::independent_approve_state_phase::execution_reserve_invoking(state, &operation, now)?;
    let (wire, request) = exact(&invoking)?;
    let response = transport.exchange("revocation-execution-reserve", wire, now);
    let response = match response {
        Ok(value) => value,
        Err(error) => {
            crate::independent_approve_state_phase::execution_reserve_unknown(
                state, &operation, now,
            )?;
            return Err(error);
        }
    };
    crate::independent_approve_state_phase::execution_reserve_unknown(state, &operation, now)?;
    let reservation = decode_endpoint_revocation_execution_reservation_strict(&response)
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let pin = pin(config, now);
    verify_endpoint_revocation_execution_reservation_at(
        &reservation,
        &request,
        &pin.peer_device_ref,
        &fresh_trust(&pin, now),
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let final_request =
        attach_revocation_execution_reservation(&request.final_revoke_request, &reservation)
            .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crate::independent_approve_state_reservation::accepted(
        state,
        &operation,
        &response,
        &reservation,
        pin,
        &final_request,
        now,
    )
}

fn exact(
    value: &IndependentApproveResume,
) -> Result<
    (
        &[u8],
        crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
    ),
    AgentError,
> {
    let wire = value
        .approval
        .execution_reserve_request_json
        .as_deref()
        .ok_or(AgentError::AuthorityRollback)?
        .as_bytes();
    let request = decode_endpoint_revocation_execution_reserve_request_strict(wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.approval.execution_reserve_request.as_ref() == Some(&request))
        .then_some((wire, request))
        .ok_or(AgentError::AuthorityRollback)
}

fn pin(config: &VerifiedConfig, now: u64) -> IndependentReservationTrustPinV1 {
    let trust = &config.0.management_projection_trust;
    IndependentReservationTrustPinV1 {
        issuer: trust.issuer.clone(),
        audience: trust.audience.clone(),
        key_id: trust.key_id.clone(),
        public_key_hex: trust.public_key_hex.clone(),
        minimum_config_generation: config.0.minimum_reservation_config_generation,
        reservation_key_id: config.0.revocation_execution_reservation_key_id.clone(),
        reservation_public_key_hex: config
            .0
            .revocation_execution_reservation_public_key_hex
            .clone(),
        minimum_reservation_config_generation: config.0.minimum_reservation_config_generation,
        minimum_snapshot_revision: trust.minimum_snapshot_revision,
        peer_device_ref: config.0.authority_route.device_id.clone(),
        accepted_at_epoch_s: now,
    }
}

fn fresh_trust(
    pin: &IndependentReservationTrustPinV1,
    now: u64,
) -> EndpointRevocationExecutionReservationTrustV1<'_> {
    EndpointRevocationExecutionReservationTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        reservation_key_id: &pin.reservation_key_id,
        reservation_public_key_hex: &pin.reservation_public_key_hex,
        minimum_reservation_config_generation: pin.minimum_reservation_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        now_epoch_s: now,
    }
}
