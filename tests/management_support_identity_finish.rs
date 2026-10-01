use crowsi_credential_authority_contracts::{ManagementCommandV2, SignedAuthorityExchangeV1};
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;

use crate::management_support::NOW;

pub fn prepare(browser: &ManagementCommandV2) -> Result<AuthorityRequestV1, AgentError> {
    let ManagementCommandV2::SourceApprove {
        attempt_id,
        assertion,
        ..
    } = browser
    else {
        return Err(AgentError::RequestInvalid);
    };
    Ok(AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "finish-approval-request".into(),
        command: AuthorityCommand::FinishFreshUserVerification(FinishFreshUvCommand {
            command_id: "finish-approval-command".into(),
            attempt_id: attempt_id.clone(),
            credential_id: assertion.credential_id.clone(),
            client_data_json_base64url: assertion.client_data_json_base64url.clone(),
            authenticator_data_base64url: assertion.authenticator_data_base64url.clone(),
            signature_der_base64url: assertion.signature_der_base64url.clone(),
        }),
        evidence: Vec::new(),
    })
}

pub fn exchange(
    request: &AuthorityRequestV1,
    begin: &SignedAuthorityExchangeV1,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let AuthorityCommand::FinishFreshUserVerification(finish) = &request.command else {
        return Err(AgentError::RequestInvalid);
    };
    let AuthorityCommand::BeginFreshUserVerification(command) = &begin.request.command else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let ResponseOutcome::Committed {
        result: AuthorityResult::FreshUvBegun(options),
    } = &begin.response.outcome
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    if finish.attempt_id != options.attempt_id || finish.credential_id != options.credential_id {
        return Err(AgentError::RequestInvalid);
    }
    let mut fresh = FreshUvV1 {
        schema: FRESH_UV_SCHEMA.into(),
        proof_id: "fresh-approval-proof".into(),
        credential_id: finish.credential_id.clone(),
        authenticator_key_fingerprint: "ab".repeat(32),
        kind: AuthenticatorKindDto::DeviceBoundPasskey,
        user_verified: true,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 15,
        challenge: options.challenge.clone(),
        attempt_id: finish.attempt_id.clone(),
        identity_nonce: command.identity_nonce.clone(),
        source_device_id: command.source_device_id.clone(),
        service_id: command.service_id.clone(),
        pairwise_subject: command.pairwise_subject.clone(),
        session_ref: command.session_ref.clone(),
        operation_digest_sha256: command.operation_digest_sha256.clone(),
        subject_epoch: command.subject_epoch,
        service_epoch: command.service_epoch,
        device_epoch: command.device_epoch,
        session_epoch: command.session_epoch,
        account_binding_sha256: "1a".repeat(32),
        key_id: "uv-key".into(),
        signature: String::new(),
    };
    fresh.signature = hex::encode(
        key(6)
            .sign(&canonical_fresh_uv(&fresh).map_err(|_| AgentError::ResponseInvalid)?)
            .to_bytes(),
    );
    let digest = command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: 1,
        issued_at_epoch_s: NOW,
        expires_at_epoch_s: NOW + 15,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::FreshUvFinished { document: fresh },
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
