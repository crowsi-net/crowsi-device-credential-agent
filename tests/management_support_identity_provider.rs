include!("management_support_identity_provider_cancellation.rs");

impl IdentityEvidenceProvider for FakeIdentity {
    fn current_identity(
        &self,
        _: &crowsi_device_credential_agent::AgentConfigDocument,
        _: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Ok(self.current.clone())
    }
    fn prepare_begin_fresh_uv(
        &self,
        config: &crowsi_device_credential_agent::AgentConfigDocument,
        identity: &SignedAuthorityExchangeV1,
        prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
        _: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        crate::management_support_identity_fresh::prepare(config, identity, prepared)
    }
    fn invoke_begin_fresh_uv(
        &self,
        _: &crowsi_device_credential_agent::AgentConfigDocument,
        request: &AuthorityRequestV1,
        _: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.begin_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.clone());
        crate::management_support_identity_fresh::exchange(request)
    }
    fn prepare_finish_fresh_uv(
        &self,
        browser: &crowsi_credential_authority_contracts::ManagementCommandV2,
    ) -> Result<AuthorityRequestV1, AgentError> {
        crate::management_support_identity_finish::prepare(browser)
    }
    fn invoke_finish_fresh_uv(
        &self,
        _: &crowsi_device_credential_agent::AgentConfigDocument,
        request: &AuthorityRequestV1,
        _: &crowsi_credential_authority_contracts::ManagementCommandV2,
        _: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.finish_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.clone());
        if std::mem::take(
            &mut *self
                .fail_finish_once
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?,
        ) {
            return Err(AgentError::AuthorityUnavailable);
        }
        let begin = self
            .begin_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .last()
            .cloned()
            .ok_or(AgentError::AuthorityRollback)?;
        let begin = crate::management_support_identity_fresh::exchange(&begin)?;
        crate::management_support_identity_finish::exchange(request, &begin)
    }
    fn prepare_current_identity(
        &self,
        _: &crowsi_device_credential_agent::AgentConfigDocument,
        now: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        self.prepare_current(now)
    }
    fn invoke_current_identity(
        &self,
        _: &crowsi_device_credential_agent::AgentConfigDocument,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.current_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.clone());
        if std::mem::take(
            &mut *self
                .fail_current_once
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?,
        ) {
            return Err(AgentError::AuthorityUnavailable);
        }
        crate::management_support_identity_current_approval::exchange_at(request, now)
    }

    fn prepare_source_revocation_begin(
        &self,
        prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
        fresh: &ihat_identity_assertion_contracts::FreshUvV1,
        now: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        crate::management_support_identity_revocation::prepare(prepared, fresh, now)
    }

    fn invoke_source_revocation_begin(
        &self,
        _: &crowsi_device_credential_agent::AgentConfigDocument,
        prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
        _: &ihat_identity_assertion_contracts::FreshUvV1,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.revocation_begin_requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(request.clone());
        if std::mem::take(
            &mut *self
                .fail_revocation_begin_once
                .lock()
                .map_err(|_| AgentError::AuthorityUnavailable)?,
        ) {
            return Err(AgentError::AuthorityUnavailable);
        }
        crate::management_support_identity_revocation::exchange(prepared, request, now)
    }

    fn prepare_source_revocation_final(
        &self,
        prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
        begun: &SignedAuthorityExchangeV1,
    ) -> Result<Option<AuthorityRequestV1>, AgentError> {
        crate::management_support_identity_revocation::final_request(prepared, begun)
    }

    fn invoke_source_revocation_final(
        &self,
        _: &crowsi_credential_authority_contracts::EndpointAuthorityResponseTrustV2<'_>,
        prepared: &crowsi_credential_authority_contracts::EndpointPreparedOperationV2,
        begun: &SignedAuthorityExchangeV1,
        _: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
        _: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1,
        _: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
        _: &str,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.invoke_revocation_final(prepared, begun, request, now)
    }

    management_support_identity_provider_cancellation_methods!();
}
