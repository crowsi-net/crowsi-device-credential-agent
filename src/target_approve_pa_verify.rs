use crowsi_windows_operation_contracts::{
    OPERATION_AUTHORIZATION_AUDIENCE, OPERATION_AUTHORIZATION_ISSUER, OPERATION_WORKLOAD_ID,
    OperationOnlyAction, OperationOnlyRequest, authorization_signing_bytes,
    decode_operation_request, operation_request_digest,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    AgentError, config::AgentConfigDocument, target_approve_state_types::TargetApproveResume,
};

pub(crate) fn response(
    config: &AgentConfigDocument,
    value: &TargetApproveResume,
    wire: &[u8],
    now: u64,
) -> Result<OperationOnlyRequest, AgentError> {
    let output = decode_operation_request(wire).map_err(|_| AgentError::TargetKeyProofInvalid)?;
    let input = value
        .approval
        .pa_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
        &input.current_identity_exchange,
    )
    .map_err(|_| AgentError::AuthorityResponseInvalid)?;
    let status = &identity.current_status;
    let binding = &output.pa_authorization.binding;
    let exact = output.request_id == input.sign_intent.request_id
        && output.credential_id == input.sign_intent.credential_id
        && output.expected_revision == input.sign_intent.expected_revision
        && output.credential_class == input.sign_intent.credential_class
        && &output.current_device_status == status
        && matches!(&output.action, OperationOnlyAction::Sign { algorithm, digest_sha256 }
            if *algorithm == input.sign_intent.algorithm
                && digest_sha256 == &input.sign_intent.digest_sha256)
        && output.pa_authorization.issuer == OPERATION_AUTHORIZATION_ISSUER
        && output.pa_authorization.key_id == config.pa_authorization_route.response_key_id
        && input.target_device_proof.issued_at_epoch_s <= output.pa_authorization.issued_at_epoch_s
        && output.pa_authorization.issued_at_epoch_s <= now
        && output.pa_authorization.issued_at_epoch_s < output.pa_authorization.expires_at_epoch_s
        && now < output.pa_authorization.expires_at_epoch_s
        && output.pa_authorization.expires_at_epoch_s
            <= input.target_device_proof.expires_at_epoch_s
        && binding.service_id == status.service_id
        && binding.pairwise_subject == status.pairwise_subject
        && binding.device_id == status.device_id
        && binding.device_proof_key_ref == status.device_proof_key_ref
        && binding.session_ref == status.session_ref
        && binding.device_posture == status.device_posture.state
        && binding.device_posture_revision == status.device_posture.revision
        && binding.subject_revocation_epoch == status.revocation_epochs.subject
        && binding.service_revocation_epoch == status.revocation_epochs.service
        && binding.device_revocation_epoch == status.revocation_epochs.device
        && binding.session_revocation_epoch == status.revocation_epochs.session
        && binding.workload_id == OPERATION_WORKLOAD_ID
        && binding.audience == OPERATION_AUTHORIZATION_AUDIENCE
        && binding.action == "sign:ed25519"
        && binding.nonce == status.nonce
        && operation_request_digest(&output)
            .is_ok_and(|digest| digest == binding.request_digest_sha256);
    if !exact {
        return Err(AgentError::TargetKeyProofInvalid);
    }
    let payload = authorization_signing_bytes(&output.pa_authorization)
        .map_err(|_| AgentError::TargetKeyProofInvalid)?;
    verify(
        &config.pa_authorization_route.response_public_key_hex,
        &output.pa_authorization.signature_hex,
        &payload,
    )?;
    Ok(output)
}

fn verify(public: &str, signature: &str, payload: &[u8]) -> Result<(), AgentError> {
    let key: [u8; 32] = lower_hex(public, 32)?
        .try_into()
        .map_err(|_| AgentError::TargetKeyProofInvalid)?;
    let signature: [u8; 64] = lower_hex(signature, 64)?
        .try_into()
        .map_err(|_| AgentError::TargetKeyProofInvalid)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| AgentError::TargetKeyProofInvalid)?;
    if key.is_weak()
        || key
            .verify_strict(payload, &Signature::from_bytes(&signature))
            .is_err()
    {
        return Err(AgentError::TargetKeyProofInvalid);
    }
    Ok(())
}

fn lower_hex(value: &str, bytes: usize) -> Result<Vec<u8>, AgentError> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AgentError::TargetKeyProofInvalid);
    }
    hex::decode(value).map_err(|_| AgentError::TargetKeyProofInvalid)
}
