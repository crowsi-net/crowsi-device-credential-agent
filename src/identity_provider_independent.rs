macro_rules! identity_provider_independent_methods {
    () => {
fn prepare_independent_revocation_approval(
    &self,
    _config: &AgentConfigDocument,
    _prepared: &EndpointPreparedOperationV2,
    _begun: &SignedAuthorityExchangeV1,
    _current: &SignedAuthorityExchangeV1,
    _now_epoch_s: u64,
) -> Result<AuthorityRequestV1, AgentError> {
    Err(AgentError::FreshUserVerificationRequired)
}

#[allow(clippy::too_many_arguments)]
fn invoke_independent_revocation_approval(
    &self,
    _trust: &EndpointAuthorityResponseTrustV2<'_>,
    _approval_key_id: &str,
    _approval_public_key_hex: &str,
    _prepared: &EndpointPreparedOperationV2,
    _begun: &SignedAuthorityExchangeV1,
    _current: &SignedAuthorityExchangeV1,
    _request: &AuthorityRequestV1,
    _wire: &str,
    _historic: bool,
    _now_epoch_s: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    Err(AgentError::FreshUserVerificationRequired)
}

fn prepare_independent_revocation_final(
    &self,
    _approval_key_id: &str,
    _approval_public_key_hex: &str,
    _prepared: &EndpointPreparedOperationV2,
    _begun: &SignedAuthorityExchangeV1,
    _current: &SignedAuthorityExchangeV1,
    _approval: &SignedAuthorityExchangeV1,
) -> Result<AuthorityRequestV1, AgentError> {
    Err(AgentError::FreshUserVerificationRequired)
}

#[allow(clippy::too_many_arguments)]
fn invoke_independent_revocation_final(
    &self,
    _trust: &EndpointAuthorityResponseTrustV2<'_>,
    _approval_key_id: &str,
    _approval_public_key_hex: &str,
    _prepared: &EndpointPreparedOperationV2,
    _begun: &SignedAuthorityExchangeV1,
    _current: &SignedAuthorityExchangeV1,
    _approval: &SignedAuthorityExchangeV1,
    _reserve: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
    _reservation: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1,
    _reservation_trust: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
    _expected_peer_device_ref: &str,
    _request: &AuthorityRequestV1,
    _wire: &str,
    _historic: bool,
    _now_epoch_s: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    Err(AgentError::FreshUserVerificationRequired)
}
    };
}
