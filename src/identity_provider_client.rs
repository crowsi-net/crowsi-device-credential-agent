use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointPreparedOperationV2, ManagementCommandV2,
    SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::{AuthorityRequestV1, FreshUvV1};

use crate::{AgentError, config::AgentConfigDocument, identity_provider::IdentityEvidenceProvider};

include!("identity_provider_client_cancel.rs");
include!("identity_provider_client_independent.rs");

impl<T: crate::transport::AuthorityTransport> IdentityEvidenceProvider
    for crate::identity_client::IdentityAuthorityClient<T>
{
    fn current_identity(
        &self,
        config: &AgentConfigDocument,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.issue(config, now)
    }

    fn prepare_current_identity(
        &self,
        config: &AgentConfigDocument,
        now: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        self.prepare_current(config, now)
    }

    fn invoke_current_identity(
        &self,
        config: &AgentConfigDocument,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.invoke_current(config, request, now)
    }

    fn prepare_begin_fresh_uv(
        &self,
        config: &AgentConfigDocument,
        identity: &SignedAuthorityExchangeV1,
        prepared: &EndpointPreparedOperationV2,
        now: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        self.prepare_begin(config, identity, prepared, now)
    }

    fn invoke_begin_fresh_uv(
        &self,
        config: &AgentConfigDocument,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.invoke_begin(config, request, now)
    }

    fn prepare_finish_fresh_uv(
        &self,
        browser: &ManagementCommandV2,
    ) -> Result<AuthorityRequestV1, AgentError> {
        self.prepare_finish(browser)
    }

    fn invoke_finish_fresh_uv(
        &self,
        config: &AgentConfigDocument,
        request: &AuthorityRequestV1,
        browser: &ManagementCommandV2,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        self.invoke_finish(config, request, browser, now)
    }

    fn prepare_source_revocation_begin(
        &self,
        prepared: &EndpointPreparedOperationV2,
        fresh: &FreshUvV1,
        now: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        crate::source_approve_revocation_request::begin(&self.sender, prepared, fresh, now)
    }

    fn invoke_source_revocation_begin(
        &self,
        config: &AgentConfigDocument,
        prepared: &EndpointPreparedOperationV2,
        fresh: &FreshUvV1,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        crate::source_approve_revocation_invoke::begin(
            &self.transport,
            config,
            prepared,
            fresh,
            request,
            now,
        )
    }

    fn prepare_source_revocation_final(
        &self,
        prepared: &EndpointPreparedOperationV2,
        begun: &SignedAuthorityExchangeV1,
    ) -> Result<Option<AuthorityRequestV1>, AgentError> {
        crate::source_approve_revocation_final_request::build(prepared, begun)
    }

    fn invoke_source_revocation_final(
        &self,
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
        crate::source_approve_revocation_invoke::finalize_reserved_with_trust(
            &self.transport,
            trust,
            prepared,
            begun,
            reserve,
            reservation,
            reservation_trust,
            expected_peer_device_ref,
            request,
            now,
        )
    }

    identity_provider_client_cancel_methods!();
    identity_provider_client_independent_methods!();
}
