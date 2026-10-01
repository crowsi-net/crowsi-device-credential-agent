#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_reserved<T: AuthorityTransport>(
    transport: &T,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    approval: &SignedAuthorityExchangeV1,
    reserve: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
    reservation: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1,
    reservation_trust: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
    expected_peer_device_ref: &str,
    request: &AuthorityRequestV1,
    wire: &str,
    historic: bool,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crate::independent_approve_invoke_exchange::pinned(approval, trust, "approve_revocation")?;
    crowsi_credential_authority_contracts::verify_endpoint_revocation_execution_reservation_historic(
        reservation,
        reserve,
        expected_peer_device_ref,
        reservation_trust,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    crate::independent_approve_final_request_validation::validate(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        approval,
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
    let exchange = crate::independent_approve_invoke_exchange::invoke(
        transport,
        trust,
        request,
        wire,
        request.command.type_name(),
        historic,
        now,
    )?;
    crate::independent_approve_response_final::validate_reserved(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        approval,
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
