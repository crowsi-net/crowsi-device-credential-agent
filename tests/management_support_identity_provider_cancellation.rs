macro_rules! management_support_identity_provider_cancellation_methods {
    () => {
fn invoke_cancel_pending_revocation(
    &self,
    _: &crowsi_credential_authority_contracts::EndpointAuthorityResponseTrustV2<'_>,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    self.cancel_pending_requests
        .lock()
        .map_err(|_| AgentError::AuthorityUnavailable)?
        .push(request.clone());
    let mut cached = self
        .cancel_pending_response
        .lock()
        .map_err(|_| AgentError::AuthorityUnavailable)?;
    let exchange = match cached.as_ref() {
        Some(value) if value.request == *request => value.clone(),
        Some(_) => return Err(AgentError::AuthorityRollback),
        None => {
            let value = crate::management_support_identity_cancellation::cancel(request, now)?;
            *cached = Some(value.clone());
            value
        }
    };
    if std::mem::take(
        &mut *self
            .fail_cancel_pending_once
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?,
    ) {
        return Err(AgentError::AuthorityUnavailable);
    }
    Ok(exchange)
}

fn invoke_pending_cancellation_ack(
    &self,
    config: &crowsi_device_credential_agent::AgentConfigDocument,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    self.cleanup_ack_requests
        .lock()
        .map_err(|_| AgentError::AuthorityUnavailable)?
        .push(request.clone());
    let exchange = crate::management_support_identity_cancellation::ack(
        request,
        &config.authority_response_key_id,
        config.minimum_identity_config_generation,
        now,
    )?;
    if std::mem::take(
        &mut *self
            .fail_cleanup_ack_once
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?,
    ) {
        return Err(AgentError::AuthorityUnavailable);
    }
    Ok(exchange)
}
    };
}
