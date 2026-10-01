macro_rules! identity_provider_client_independent_methods {
    () => {
fn prepare_independent_revocation_approval(
    &self,
    config: &AgentConfigDocument,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<AuthorityRequestV1, AgentError> {
    crate::independent_approve_request::build(config, self.uid, prepared, begun, current, now)
}

fn invoke_independent_revocation_approval(
    &self,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
    wire: &str,
    historic: bool,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crate::independent_approve_invoke::approval(
        &self.transport,
        trust,
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        request,
        wire,
        historic,
        now,
    )
}

fn prepare_independent_revocation_final(
    &self,
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    approval: &SignedAuthorityExchangeV1,
) -> Result<AuthorityRequestV1, AgentError> {
    crate::independent_approve_final_request::build(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        approval,
    )
}

fn invoke_independent_revocation_final(
    &self,
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
    crate::independent_approve_invoke::finalize_reserved(
        &self.transport,
        trust,
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
        request,
        wire,
        historic,
        now,
    )
}
    };
}
