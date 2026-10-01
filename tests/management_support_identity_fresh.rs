use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1, endpoint_operation_digest,
    identity_evidence_from_exchange,
};
use crowsi_device_credential_agent::{AgentConfigDocument, AgentError};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;

use crate::management_support::NOW;

pub fn prepare(
    config: &AgentConfigDocument,
    identity: &SignedAuthorityExchangeV1,
    prepared: &EndpointPreparedOperationV2,
) -> Result<AuthorityRequestV1, AgentError> {
    let metadata =
        identity_evidence_from_exchange(identity).map_err(|_| AgentError::IdentityUnavailable)?;
    let epochs = &metadata.assertion.revocation_epochs;
    Ok(AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: format!("begin-{}", &prepared.operation_id[..16]),
        command: AuthorityCommand::BeginFreshUserVerification(BeginFreshUvCommand {
            command_id: format!("begin-command-{}", &prepared.operation_id[..16]),
            credential_id: config.user_verification_credential_id.clone(),
            identity_nonce: metadata.assertion.nonce.clone(),
            source_device_id: metadata.assertion.device_id.clone(),
            service_id: metadata.assertion.service_id.clone(),
            pairwise_subject: metadata.assertion.pairwise_subject.clone(),
            session_ref: metadata.assertion.session_ref.clone(),
            operation_digest_sha256: endpoint_operation_digest(prepared)
                .map_err(|_| AgentError::RequestInvalid)?,
            subject_epoch: epochs.subject,
            service_epoch: epochs.service,
            device_epoch: epochs.device,
            session_epoch: epochs.session,
        }),
        evidence: Vec::new(),
    })
}

pub fn exchange(request: &AuthorityRequestV1) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let AuthorityCommand::BeginFreshUserVerification(command) = &request.command else {
        return Err(AgentError::RequestInvalid);
    };
    let digest = command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
    let options = FreshUvRequestOptions {
        attempt_id: format!("attempt-{}", &command.operation_digest_sha256[..16]),
        challenge: "challenge-a".into(),
        rp_id: "example.test".into(),
        origin: "https://example.test".into(),
        credential_id: command.credential_id.clone(),
        timeout_ms: 20_000,
        expires_at_epoch_s: NOW + 20,
        command_binding_sha256: digest.clone(),
    };
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: 1,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 20,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvBegun(options),
        },
        key_id: "authority-response-key".into(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        key(3)
            .sign(&canonical_response(&response).map_err(|_| AgentError::ResponseInvalid)?)
            .to_bytes(),
    );
    Ok(SignedAuthorityExchangeV1 {
        request: request.clone(),
        response,
    })
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
