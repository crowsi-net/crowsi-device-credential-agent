use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointPreparedOperationV2,
    EndpointReservedRevocationFinalResponseTrustV1,
    EndpointRevocationExecutionReservationHistoricTrustV1,
    EndpointRevocationExecutionReservationV1, EndpointRevocationExecutionReserveRequestV1,
    SignedAuthorityExchangeV1, verify_endpoint_reserved_revocation_final_exchange_historic_at,
};

use crate::AgentError;

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_reserved(
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    approval: &SignedAuthorityExchangeV1,
    reserve: &EndpointRevocationExecutionReserveRequestV1,
    reservation: &EndpointRevocationExecutionReservationV1,
    reservation_trust: &EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
    expected_peer_device_ref: &str,
    response_trust: &EndpointAuthorityResponseTrustV2<'_>,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    crate::independent_approve_final_request_validation::validate(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        approval,
        &reserve.final_revoke_request,
    )?;
    verify_endpoint_reserved_revocation_final_exchange_historic_at(
        exchange,
        reserve,
        reservation,
        expected_peer_device_ref,
        reservation_trust,
        &EndpointReservedRevocationFinalResponseTrustV1 {
            key_id: response_trust.key_id,
            public_key_hex: response_trust.public_key_hex,
            minimum_config_generation: response_trust.minimum_config_generation,
            now_epoch_s: now,
        },
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)
}

pub(super) fn reservation_trust(
    pin: &crate::independent_approve_state_types::IndependentReservationTrustPinV1,
) -> EndpointRevocationExecutionReservationHistoricTrustV1<'_> {
    EndpointRevocationExecutionReservationHistoricTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        reservation_key_id: &pin.reservation_key_id,
        reservation_public_key_hex: &pin.reservation_public_key_hex,
        minimum_reservation_config_generation: pin.minimum_reservation_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        accepted_at_epoch_s: pin.accepted_at_epoch_s,
    }
}
