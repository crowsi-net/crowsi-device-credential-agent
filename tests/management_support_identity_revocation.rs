use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, SignedAuthorityExchangeV1,
    revocation_begin_command_id,
};
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;

pub fn prepare(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    now: u64,
) -> Result<AuthorityRequestV1, AgentError> {
    let proof_id = "revocation-sender-proof";
    let command_id =
        revocation_begin_command_id(prepared).map_err(|_| AgentError::RequestInvalid)?;
    let command = match &prepared.intent {
        ManagementIntentV2::DeviceRevocation {
            service_id,
            target_device_ref,
            expected_device_revocation_epoch,
            ..
        } => AuthorityCommand::BeginDeviceRevocation(BeginDeviceRevocationCommand {
            command_id,
            finalize_command_id: prepared.operation_id.clone(),
            service_id: service_id.clone(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            source_device_id: prepared.source_device_ref.clone(),
            source_session_ref: prepared.source_session_ref.clone(),
            target_device_id: target_device_ref.clone(),
            expected_device_epoch: *expected_device_revocation_epoch,
            identity_nonce: prepared.source_identity_nonce.clone(),
            sender_proof_id: proof_id.into(),
            authentication: authentication(fresh),
        }),
        ManagementIntentV2::SessionRevocation {
            service_id,
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => AuthorityCommand::BeginSessionRevocation(BeginSessionRevocationCommand {
            command_id,
            finalize_command_id: prepared.operation_id.clone(),
            service_id: service_id.clone(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            source_device_id: prepared.source_device_ref.clone(),
            source_session_ref: prepared.source_session_ref.clone(),
            target_session_ref: target_session_ref.clone(),
            expected_session_epoch: *expected_session_revocation_epoch,
            identity_nonce: prepared.source_identity_nonce.clone(),
            sender_proof_id: proof_id.into(),
            authentication: authentication(fresh),
        }),
        ManagementIntentV2::DeviceTransfer { .. } => return Err(AgentError::RequestInvalid),
    };
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "revocation-begin-request".into(),
        command,
        evidence: vec![AuthorityEvidence::FreshUv(fresh.clone())],
    };
    let binding = command_digest(&request).map_err(|_| AgentError::RequestInvalid)?;
    request
        .evidence
        .push(AuthorityEvidence::Signed(sender(proof_id, &binding, now)?));
    Ok(request)
}

pub fn exchange(
    prepared: &EndpointPreparedOperationV2,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let target = match &request.command {
        AuthorityCommand::BeginDeviceRevocation(command) => &command.target_device_id,
        AuthorityCommand::BeginSessionRevocation(_) => prepared
            .revocation
            .as_ref()
            .map(|value| &value.target_device_ref)
            .ok_or(AgentError::RequestInvalid)?,
        _ => return Err(AgentError::RequestInvalid),
    };
    let independent = target != &prepared.source_device_ref;
    let result = RevocationCeremonyMetadata {
        attempt_id: "revocation-attempt".into(),
        finalize_command_id: prepared.operation_id.clone(),
        target_digest: "33".repeat(32),
        expires_at_epoch_s: now + 15,
        independent_approval_required: independent,
        state: if independent {
            RevocationCeremonyStateDto::AwaitingIndependentApproval
        } else {
            RevocationCeremonyStateDto::ReadyToFinalize
        },
        approval_nonce: independent.then(|| "independent-approval-nonce".into()),
    };
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(request).map_err(|_| AgentError::RequestInvalid)?,
        config_generation: 1,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 15,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::RevocationBegun(result),
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

fn sender(id: &str, binding: &str, now: u64) -> Result<SignedEvidenceV1, AgentError> {
    let mut value = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: id.into(),
        key_id: "session-sender-key".into(),
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 15,
        binding_sha256: binding.into(),
        signature: String::new(),
    };
    value.signature = hex::encode(
        key(7)
            .sign(&canonical_signed_evidence(&value).map_err(|_| AgentError::RequestInvalid)?)
            .to_bytes(),
    );
    Ok(value)
}

include!("management_support_identity_revocation_authentication.rs");
include!("management_support_identity_revocation_final.rs");

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
