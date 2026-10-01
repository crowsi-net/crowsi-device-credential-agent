#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_reserved_with_trust<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    reserve: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
    reservation: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1,
    reservation_trust: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
    expected_peer_device_ref: &str,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_reservation_historic(
        reservation,
        reserve,
        expected_peer_device_ref,
        reservation_trust,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    crate::source_approve_revocation_final_request::validate(
        prepared,
        begun,
        &reserve.final_revoke_request,
    )?;
    let attached = crowsi_credential_authority_contracts::attach_revocation_execution_reservation(
        &reserve.final_revoke_request,
        reservation,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    if attached != *request {
        return Err(AgentError::AuthorityRollback);
    }
    let exchange = exchange(transport, trust, request, final_name(prepared)?, true, now)?;
    crate::source_approve_revocation_response_final::validate_reserved(
        prepared,
        begun,
        reserve,
        reservation,
        reservation_trust,
        expected_peer_device_ref,
        trust,
        &exchange,
        now,
    )?;
    Ok(exchange)
}
