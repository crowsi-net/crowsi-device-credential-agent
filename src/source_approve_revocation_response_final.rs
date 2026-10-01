use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointPreparedOperationV2,
    EndpointReservedRevocationFinalResponseTrustV1,
    EndpointRevocationExecutionReservationHistoricTrustV1,
    EndpointRevocationExecutionReservationV1, EndpointRevocationExecutionReserveRequestV1,
    SignedAuthorityExchangeV1, verify_endpoint_reserved_revocation_final_exchange_historic_at,
};

use crate::{AgentError, source_approve_state_types::SourceReservationTrustPinV1};

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_reserved(
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    reserve: &EndpointRevocationExecutionReserveRequestV1,
    reservation: &EndpointRevocationExecutionReservationV1,
    reservation_trust: &EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
    expected_peer_device_ref: &str,
    response_trust: &EndpointAuthorityResponseTrustV2<'_>,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    if reserve.prepared != *prepared
        || reserve.begin_exchange != *begun
        || reserve.approval_exchange.is_some()
    {
        return Err(AgentError::AuthorityResponseInvalid);
    }
    crate::source_approve_revocation_final_request::validate(
        prepared,
        begun,
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
    pin: &SourceReservationTrustPinV1,
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

#[cfg(test)]
pub(crate) fn validate_unreserved_for_test(
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    exchange: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<(), AgentError> {
    crate::source_approve_revocation_final_request::validate(prepared, begun, &exchange.request)?;
    let metadata = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?;
    if now >= metadata.expires_at_epoch_s
        || exchange.response.issued_at_epoch_s >= metadata.expires_at_epoch_s
    {
        return Err(AgentError::AuthorityResponseInvalid);
    }
    crowsi_credential_authority_contracts::validate_authority_exchange(
        exchange,
        exchange.request.command.type_name(),
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    crowsi_credential_authority_contracts::validate_revocation_final_exchange_against_begin(
        prepared, begun, exchange,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)
}
