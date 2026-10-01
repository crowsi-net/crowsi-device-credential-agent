use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;

pub fn cancel(
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let AuthorityCommand::CancelPendingRevocation(command) = &request.command else {
        return Err(AgentError::RequestInvalid);
    };
    let [AuthorityEvidence::Signed(token)] = request.evidence.as_slice() else {
        return Err(AgentError::RequestInvalid);
    };
    response(
        request,
        AuthorityResult::PendingRevocationCancelled(PendingRevocationCancelledMetadata {
            attempt_id: command.attempt_id.clone(),
            finalize_command_id: command.finalize_command_id.clone(),
            target_digest_sha256: command.target_digest_sha256.clone(),
            cancellation_id: token.proof_id.clone(),
        }),
        "authority-response-key",
        1,
        3,
        now,
    )
}

pub fn ack(
    request: &AuthorityRequestV1,
    key_id: &str,
    generation: u64,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let AuthorityCommand::AcknowledgePendingCancellation(command) = &request.command else {
        return Err(AgentError::RequestInvalid);
    };
    let [AuthorityEvidence::Signed(token)] = request.evidence.as_slice() else {
        return Err(AgentError::RequestInvalid);
    };
    let byte = if key_id == "rotated-authority-response-key" {
        10
    } else {
        3
    };
    response(
        request,
        AuthorityResult::PendingCancellationAcknowledged(PendingCancellationAcknowledgedMetadata {
            cancellation_id: command.cancellation_id.clone(),
            cleanup_id: token.proof_id.clone(),
        }),
        key_id,
        generation,
        byte,
        now,
    )
}

fn response(
    request: &AuthorityRequestV1,
    result: AuthorityResult,
    key_id: &str,
    generation: u64,
    byte: u8,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(request).map_err(|_| AgentError::RequestInvalid)?,
        config_generation: generation,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(30),
        outcome: ResponseOutcome::Committed { result },
        key_id: key_id.into(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        SigningKey::from_bytes(&[byte; 32])
            .sign(&canonical_response(&response).map_err(|_| AgentError::ResponseInvalid)?)
            .to_bytes(),
    );
    Ok(SignedAuthorityExchangeV1 {
        request: request.clone(),
        response,
    })
}
