use crowsi_credential_authority_contracts::{
    EndpointAuthorityResponseTrustV2, EndpointPreparedOperationV2, ManagementCommandV2,
    SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use ihat_identity_assertion_contracts::FreshUvV1;

use crate::{AgentError, config::AgentConfigDocument};

include!("identity_provider_independent.rs");

pub trait IdentityEvidenceProvider {
    /// Returns one fully correlated and authority-signed current identity exchange.
    ///
    /// # Errors
    /// Fails closed when current identity cannot be issued or verified.
    fn current_identity(
        &self,
        config: &AgentConfigDocument,
        now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError>;

    fn prepare_current_identity(
        &self,
        _config: &AgentConfigDocument,
        _now_epoch_s: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        Err(AgentError::IdentityUnavailable)
    }

    fn invoke_current_identity(
        &self,
        _config: &AgentConfigDocument,
        _request: &AuthorityRequestV1,
        _now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Err(AgentError::IdentityUnavailable)
    }

    fn prepare_begin_fresh_uv(
        &self,
        _config: &AgentConfigDocument,
        _identity: &SignedAuthorityExchangeV1,
        _prepared: &EndpointPreparedOperationV2,
        _now_epoch_s: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn invoke_begin_fresh_uv(
        &self,
        _config: &AgentConfigDocument,
        _request: &AuthorityRequestV1,
        _now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn prepare_finish_fresh_uv(
        &self,
        _browser: &ManagementCommandV2,
    ) -> Result<AuthorityRequestV1, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn invoke_finish_fresh_uv(
        &self,
        _config: &AgentConfigDocument,
        _request: &AuthorityRequestV1,
        _browser: &ManagementCommandV2,
        _now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn prepare_source_revocation_begin(
        &self,
        _prepared: &EndpointPreparedOperationV2,
        _fresh: &FreshUvV1,
        _now_epoch_s: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn invoke_source_revocation_begin(
        &self,
        _config: &AgentConfigDocument,
        _prepared: &EndpointPreparedOperationV2,
        _fresh: &FreshUvV1,
        _request: &AuthorityRequestV1,
        _now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn prepare_source_revocation_final(
        &self,
        _prepared: &EndpointPreparedOperationV2,
        _begun: &SignedAuthorityExchangeV1,
    ) -> Result<Option<AuthorityRequestV1>, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn invoke_source_revocation_final(
        &self,
        _trust: &EndpointAuthorityResponseTrustV2<'_>,
        _prepared: &EndpointPreparedOperationV2,
        _begun: &SignedAuthorityExchangeV1,
        _reserve: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReserveRequestV1,
        _reservation: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationV1,
        _reservation_trust: &crowsi_credential_authority_contracts::EndpointRevocationExecutionReservationHistoricTrustV1<'_>,
        _expected_peer_device_ref: &str,
        _request: &AuthorityRequestV1,
        _now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Err(AgentError::FreshUserVerificationRequired)
    }

    fn invoke_cancel_pending_revocation(
        &self,
        _trust: &EndpointAuthorityResponseTrustV2<'_>,
        _request: &AuthorityRequestV1,
        _now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Err(AgentError::IdentityUnavailable)
    }

    fn invoke_pending_cancellation_ack(
        &self,
        _config: &AgentConfigDocument,
        _request: &AuthorityRequestV1,
        _now_epoch_s: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        Err(AgentError::IdentityUnavailable)
    }

    identity_provider_independent_methods!();
}
