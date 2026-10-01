struct Context<'a> {
    approval_key_id: &'a str,
    approval_public_key: &'a str,
    begun: &'a crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    current: &'a crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    approval: &'a crowsi_credential_authority_contracts::SignedAuthorityExchangeV1,
    reserve: &'a crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
    reservation:
        &'a crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1,
    pin: &'a crate::independent_approve_state_types::IndependentReservationTrustPinV1,
    request: &'a ihat_identity_assertion_contracts::AuthorityRequestV1,
    wire: &'a str,
}

impl<'a> Context<'a> {
    fn new(value: &'a IndependentApproveResume) -> Result<Self, AgentError> {
        let (approval_key_id, approval_public_key) =
            crate::independent_approve_ceremony_context::approval_pin(value)?;
        Ok(Self {
            approval_key_id,
            approval_public_key,
            begun: crate::independent_approve_ceremony_context::begun(value)?,
            current: crate::independent_approve_ceremony_context::current(value)?,
            approval: value
                .approval
                .approval_exchange
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?,
            reserve: value
                .approval
                .execution_reserve_request
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?,
            reservation: value
                .approval
                .execution_reservation
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?,
            pin: value
                .approval
                .execution_reservation_trust
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?,
            request: value
                .approval
                .final_request
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?,
            wire: value
                .approval
                .final_request_json
                .as_deref()
                .ok_or(AgentError::AuthorityRollback)?,
        })
    }

    fn reservation_trust(&self) -> EndpointRevocationExecutionReservationHistoricTrustV1<'_> {
        crate::independent_approve_response_final::reservation_trust(self.pin)
    }
}
