macro_rules! identity_provider_client_cancel_methods {
    () => {
fn invoke_cancel_pending_revocation(
    &self,
    trust: &EndpointAuthorityResponseTrustV2<'_>,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crate::cancel_identity_invoke::historic(
        &self.transport,
        trust,
        request,
        "cancel_pending_revocation",
        now,
    )
}

fn invoke_pending_cancellation_ack(
    &self,
    config: &AgentConfigDocument,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    crate::cancel_identity_invoke::fresh(
        &self.transport,
        &crate::source_approve_revocation_invoke::trust(config),
        request,
        "acknowledge_pending_cancellation",
        now,
    )
}
    };
}
