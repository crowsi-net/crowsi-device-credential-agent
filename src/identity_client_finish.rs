use crowsi_credential_authority_contracts::{
    ManagementCommandV2, SignedAuthorityExchangeV1, fresh_uv_from_finish_exchange,
    verify_authority_exchange_at,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1, FinishFreshUvCommand,
    decode_authority_request_strict, decode_authority_response_strict,
};

use crate::{
    AgentError, config::AgentConfigDocument, identity_client::IdentityAuthorityClient,
    transport::AuthorityTransport,
};

impl<T: AuthorityTransport> IdentityAuthorityClient<T> {
    pub(crate) fn prepare_finish(
        &self,
        browser: &ManagementCommandV2,
    ) -> Result<AuthorityRequestV1, AgentError> {
        let (attempt_id, assertion) = match browser {
            ManagementCommandV2::SourceApprove {
                attempt_id,
                assertion,
                ..
            }
            | ManagementCommandV2::TargetApprove {
                attempt_id,
                assertion,
                ..
            }
            | ManagementCommandV2::ApproveRevocation {
                attempt_id,
                assertion,
                ..
            } => (attempt_id, assertion),
            _ => return Err(AgentError::RequestInvalid),
        };
        let request = AuthorityRequestV1 {
            schema: AUTHORITY_REQUEST_SCHEMA.into(),
            request_id: crate::random_id::create("finish-uv-request")?,
            command: AuthorityCommand::FinishFreshUserVerification(FinishFreshUvCommand {
                command_id: crate::random_id::create("finish-uv-command")?,
                attempt_id: attempt_id.clone(),
                credential_id: assertion.credential_id.clone(),
                client_data_json_base64url: assertion.client_data_json_base64url.clone(),
                authenticator_data_base64url: assertion.authenticator_data_base64url.clone(),
                signature_der_base64url: assertion.signature_der_base64url.clone(),
            }),
            evidence: Vec::new(),
        };
        let wire = serde_json::to_vec(&request).map_err(|_| AgentError::RequestInvalid)?;
        let decoded =
            decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
        (decoded == request)
            .then_some(request)
            .ok_or(AgentError::RequestInvalid)
    }

    pub(crate) fn invoke_finish(
        &self,
        config: &AgentConfigDocument,
        request: &AuthorityRequestV1,
        browser: &ManagementCommandV2,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        if !matches!(
            request.command,
            AuthorityCommand::FinishFreshUserVerification(_)
        ) || !request.evidence.is_empty()
        {
            return Err(AgentError::RequestInvalid);
        }
        let wire = serde_json::to_vec(request).map_err(|_| AgentError::RequestInvalid)?;
        let response = self.transport.exchange("ihat_authority_v1", &wire, now)?;
        let response = decode_authority_response_strict(&response)
            .map_err(|_| AgentError::AuthorityResponseInvalid)?;
        let exchange = SignedAuthorityExchangeV1 {
            request: request.clone(),
            response,
        };
        verify_authority_exchange_at(
            &exchange,
            "finish_fresh_user_verification",
            config.minimum_identity_config_generation,
            &config.authority_response_key_id,
            &config.authority_response_public_key_hex,
            now,
        )
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
        fresh_uv_from_finish_exchange(&exchange, browser)
            .map_err(|_| AgentError::AuthorityResponseInvalid)?;
        Ok(exchange)
    }
}
