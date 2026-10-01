use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;

pub fn response(request: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
    let request = decode_endpoint_revocation_execution_cancel_finalize_request_strict(request)
        .map_err(|_| AgentError::RequestInvalid)?;
    let request_digest = endpoint_revocation_execution_cancel_finalize_request_digest(&request)
        .map_err(|_| AgentError::RequestInvalid)?;
    let pending_digest = command_digest(&request.cancel_pending_exchange.request)
        .map_err(|_| AgentError::RequestInvalid)?;
    let response_digest =
        endpoint_signed_authority_exchange_digest(&request.cancel_pending_exchange)
            .map_err(|_| AgentError::RequestInvalid)?;
    let revision = request
        .cancellation
        .cancellation_accepted_revision
        .saturating_add(1);
    let acknowledge = acknowledge(
        &request,
        &request_digest,
        &pending_digest,
        &response_digest,
        revision,
    );
    let mut value = build(
        &request,
        request_digest,
        pending_digest,
        response_digest,
        acknowledge,
        revision,
        now,
    );
    value.cleanup_id = endpoint_revocation_execution_cancellation_cleanup_id(&value)
        .map_err(|_| AgentError::ResponseInvalid)?;
    value.token.proof_id.clone_from(&value.cleanup_id);
    value.token.binding_sha256 =
        command_digest(&value.acknowledge_request).map_err(|_| AgentError::ResponseInvalid)?;
    value.token.signature = sign(
        9,
        &canonical_signed_evidence(&value.token).map_err(|_| AgentError::ResponseInvalid)?,
    );
    value.signature = sign(
        2,
        &canonical_endpoint_revocation_execution_cancellation_cleanup(&value)
            .map_err(|_| AgentError::ResponseInvalid)?,
    );
    serde_json::to_vec(&value).map_err(|_| AgentError::ResponseInvalid)
}

fn acknowledge(
    request: &EndpointRevocationExecutionCancelFinalizeRequestV1,
    request_digest: &str,
    pending_digest: &str,
    response_digest: &str,
    revision: u64,
) -> AuthorityRequestV1 {
    AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command: AuthorityCommand::AcknowledgePendingCancellation(
            AcknowledgePendingCancellationCommand {
                command_id: request_digest.into(),
                cancellation_id: request.cancellation.cancellation_id.clone(),
                cancel_pending_command_digest_sha256: pending_digest.into(),
                cancel_pending_response_digest_sha256: response_digest.into(),
                source_device_id: request.cancellation.source_device_ref.clone(),
                cleanup_completed_revision: revision,
                authority_id: "revocation-reservation-key".into(),
            },
        ),
        evidence: Vec::new(),
    }
}

include!("management_support_cancellation_cleanup_build.rs");

fn sign(byte: u8, value: &[u8]) -> String {
    hex::encode(SigningKey::from_bytes(&[byte; 32]).sign(value).to_bytes())
}
