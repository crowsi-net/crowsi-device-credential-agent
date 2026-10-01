use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1, endpoint_operation_digest,
    identity_evidence_from_exchange, verify_authority_exchange_at,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1, AuthorityResult,
    BeginFreshUvCommand, ResponseOutcome, command_digest, decode_authority_request_strict,
    decode_authority_response_strict,
};

use crate::{
    AgentError, config::AgentConfigDocument, identity_client::IdentityAuthorityClient,
    transport::AuthorityTransport,
};

impl<T: AuthorityTransport> IdentityAuthorityClient<T> {
    pub(crate) fn prepare_begin(
        &self,
        config: &AgentConfigDocument,
        identity_exchange: &SignedAuthorityExchangeV1,
        prepared: &EndpointPreparedOperationV2,
        _now: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        let identity = identity_evidence_from_exchange(identity_exchange)
            .map_err(|_| AgentError::IdentityUnavailable)?;
        let epochs = &identity.assertion.revocation_epochs;
        let request = AuthorityRequestV1 {
            schema: AUTHORITY_REQUEST_SCHEMA.into(),
            request_id: crate::random_id::create("fresh-uv-request")?,
            command: AuthorityCommand::BeginFreshUserVerification(BeginFreshUvCommand {
                command_id: crate::random_id::create("fresh-uv-command")?,
                credential_id: config.user_verification_credential_id.clone(),
                identity_nonce: identity.assertion.nonce.clone(),
                source_device_id: identity.assertion.device_id.clone(),
                service_id: identity.assertion.service_id.clone(),
                pairwise_subject: identity.assertion.pairwise_subject.clone(),
                session_ref: identity.assertion.session_ref.clone(),
                operation_digest_sha256: endpoint_operation_digest(prepared)
                    .map_err(|_| AgentError::RequestInvalid)?,
                subject_epoch: epochs.subject,
                service_epoch: epochs.service,
                device_epoch: epochs.device,
                session_epoch: epochs.session,
            }),
            evidence: Vec::new(),
        };
        Ok(request)
    }

    pub(crate) fn invoke_begin(
        &self,
        config: &AgentConfigDocument,
        request: &AuthorityRequestV1,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        let AuthorityCommand::BeginFreshUserVerification(command) = &request.command else {
            return Err(AgentError::RequestInvalid);
        };
        let wire = serde_json::to_vec(request).map_err(|_| AgentError::RequestInvalid)?;
        let decoded =
            decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
        if decoded != *request {
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
            "begin_fresh_user_verification",
            config.minimum_identity_config_generation,
            &config.authority_response_key_id,
            &config.authority_response_public_key_hex,
            now,
        )
        .map_err(|_| AgentError::AuthorityResponseInvalid)?;
        let digest = command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
        let valid = matches!(&exchange.response.outcome, ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options)
        } if options.credential_id == command.credential_id
            && options.command_binding_sha256 == digest);
        valid
            .then_some(exchange)
            .ok_or(AgentError::AuthorityResponseInvalid)
    }
}
