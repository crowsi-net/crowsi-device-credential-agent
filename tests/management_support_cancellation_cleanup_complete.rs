use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_signed_evidence,
    command_digest,
};

pub fn response(request: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
    let request =
        decode_endpoint_revocation_execution_cancel_cleanup_complete_request_strict(request)
            .map_err(|_| AgentError::RequestInvalid)?;
    let revision = request.cleanup.cleanup_completed_revision.saturating_add(1);
    let token_issued_at = request.cleanup.token.issued_at_epoch_s;
    let mut value = EndpointRevocationExecutionCancellationCleanupCompleteV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_CLEANUP_COMPLETE_SCHEMA.into(),
        cleanup_complete_id: String::new(),
        cleanup_complete_request_sha256:
            endpoint_revocation_execution_cancel_cleanup_complete_request_digest(&request)
                .map_err(|_| AgentError::ResponseInvalid)?,
        cleanup_id: request.cleanup.cleanup_id.clone(),
        cancellation_id: request.cleanup.cancellation_id.clone(),
        acknowledge_command_digest_sha256: command_digest(&request.acknowledge_exchange.request)
            .map_err(|_| AgentError::ResponseInvalid)?,
        acknowledge_result_digest_sha256:
            endpoint_revocation_cancellation_acknowledgement_result_digest(&request)
                .map_err(|_| AgentError::ResponseInvalid)?,
        source_device_ref: request.cleanup.source_device_ref.clone(),
        cleanup_delivery_completed_revision: revision,
        cleanup_complete_config_generation: 1,
        operation: request.cleanup.operation.clone(),
        snapshot_revision: revision,
        token: token(token_issued_at),
        issuer: "crowsi-credential-authority".into(),
        audience: "endpoint-a".into(),
        config_generation: 1,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(30),
        key_id: "management-key".into(),
        signature: String::new(),
    };
    value.cleanup_complete_id =
        endpoint_revocation_execution_cancellation_cleanup_complete_id(&value)
            .map_err(|_| AgentError::ResponseInvalid)?;
    value.token.proof_id.clone_from(&value.cleanup_complete_id);
    value
        .token
        .binding_sha256
        .clone_from(&value.cleanup_complete_request_sha256);
    value.token.signature = sign(
        9,
        &canonical_signed_evidence(&value.token).map_err(|_| AgentError::ResponseInvalid)?,
    );
    value.signature = sign(
        2,
        &canonical_endpoint_revocation_execution_cancellation_cleanup_complete(&value)
            .map_err(|_| AgentError::ResponseInvalid)?,
    );
    serde_json::to_vec(&value).map_err(|_| AgentError::ResponseInvalid)
}

fn token(issued_at: u64) -> SignedEvidenceV1 {
    SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RevocationCancellationCleanupComplete,
        proof_id: String::new(),
        key_id: "revocation-reservation-key".into(),
        issued_at_epoch_s: issued_at,
        expires_at_epoch_s: issued_at.saturating_add(120),
        binding_sha256: String::new(),
        signature: String::new(),
    }
}

fn sign(byte: u8, value: &[u8]) -> String {
    hex::encode(SigningKey::from_bytes(&[byte; 32]).sign(value).to_bytes())
}
