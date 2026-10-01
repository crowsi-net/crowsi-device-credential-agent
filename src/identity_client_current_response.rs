use crowsi_credential_authority_contracts::{
    SignedAuthorityExchangeV1, identity_evidence_from_exchange, verify_authority_exchange_at,
};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityRequestV1, command_digest, decode_authority_request_strict,
    decode_authority_response_strict,
};
use std::path::Path;

use crate::{
    AgentError, config::AgentConfigDocument, identity_client::IdentityAuthorityClient,
    transport::AuthorityTransport,
};

impl<T: AuthorityTransport> IdentityAuthorityClient<T> {
    pub(crate) fn invoke_current(
        &self,
        config: &AgentConfigDocument,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &request.command else {
            return Err(AgentError::RequestInvalid);
        };
        let wire = serde_json::to_vec(request).map_err(|_| AgentError::RequestInvalid)?;
        if decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?
            != *request
        {
            return Err(AgentError::RequestInvalid);
        }
        let response = self.transport.exchange("ihat_authority_v1", &wire, now)?;
        let response = decode_authority_response_strict(&response)
            .map_err(|_| AgentError::AuthorityResponseInvalid)?;
        let exchange = SignedAuthorityExchangeV1 {
            request: request.clone(),
            response,
        };
        verify_authority_exchange_at(
            &exchange,
            "issue_current_device_identity_evidence",
            config.minimum_identity_config_generation,
            &config.authority_response_key_id,
            &config.authority_response_public_key_hex,
            now,
        )
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
        let identity = identity_evidence_from_exchange(&exchange)
            .map_err(|_| AgentError::IdentityUnavailable)?;
        let state = crate::replay::DurableSecurityState::open(
            Path::new(&config.endpoint_state_directory),
            Path::new(&config.endpoint_anchor_directory),
            self.uid,
            &config.endpoint_deployment_id,
            config.configuration_generation,
        )?;
        let locator = state.identity_locator().load(config)?;
        crate::identity_verify::identity(config, &locator, identity, &command.identity_nonce, now)?;
        command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
        Ok(exchange)
    }
}
