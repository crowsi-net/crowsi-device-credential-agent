use crate::management_support::{NOW, SESSION};
use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;
use sha2::{Digest, Sha256};
pub fn prepare_at(now: u64, sequence: u64) -> AuthorityRequestV1 {
    let proof_id = format!("approval-current-sender-proof-{sequence}");
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: format!("approval-current-request-{sequence}"),
        command: AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
            IssueCurrentDeviceIdentityEvidenceCommand {
                service_id: "service-a".into(),
                pairwise_subject: "psu_pairwise-a".into(),
                device_id: "device-a".into(),
                audience: "crowsi-management".into(),
                identity_nonce: format!("submission-current-nonce-{sequence}"),
                ttl_seconds: 30,
                session_sender_key_fingerprint: hex::encode(Sha256::digest(
                    key(7).verifying_key().to_bytes(),
                )),
                session_sender_proof_id: proof_id.clone(),
            },
        ),
        evidence: Vec::new(),
    };
    let digest = command_digest(&request).expect("current digest");
    let mut proof = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: proof_id.clone(),
        key_id: "session-sender-key".into(),
        issued_at_epoch_s: now - 1,
        expires_at_epoch_s: now + 14,
        binding_sha256: digest,
        signature: String::new(),
    };
    proof.signature = hex::encode(
        key(7)
            .sign(&canonical_signed_evidence(&proof).expect("sender"))
            .to_bytes(),
    );
    request.evidence.push(AuthorityEvidence::Signed(proof));
    request
}
pub fn exchange(request: &AuthorityRequestV1) -> Result<SignedAuthorityExchangeV1, AgentError> {
    exchange_at(request, NOW)
}

pub fn exchange_at(
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &request.command else {
        return Err(AgentError::RequestInvalid);
    };
    let mut assertion = assertion(&command.identity_nonce, now);
    assertion.signature = hex::encode(
        key(4)
            .sign(&canonical_assertion_payload(&assertion))
            .to_bytes(),
    );
    let mut status = status(&assertion);
    status.signature = hex::encode(
        key(5)
            .sign(&canonical_current_status_payload(&status))
            .to_bytes(),
    );
    let digest = command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: 1,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 20,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::IdentityEvidence(IdentityEvidenceMetadata {
                assertion,
                current_status: status,
            }),
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

fn assertion(nonce: &str, now: u64) -> DeviceIdentityAssertionV1 {
    DeviceIdentityAssertionV1 {
        schema: DEVICE_IDENTITY_ASSERTION_SCHEMA.into(),
        issuer: "ihat-authority".into(),
        audience: "crowsi-management".into(),
        service_id: "service-a".into(),
        pairwise_subject: "psu_pairwise-a".into(),
        device_id: "device-a".into(),
        device_proof_key_ref: "device-proof:sha256:device-a".into(),
        session_ref: SESSION.into(),
        device_posture: DevicePostureV1 {
            state: "compliant".into(),
            revision: 1,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: 1,
            service: 1,
            device: 1,
            session: 1,
        },
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 20,
        nonce: nonce.into(),
        key_id: "identity-key".into(),
        signature: String::new(),
    }
}

fn status(value: &DeviceIdentityAssertionV1) -> CurrentDeviceStatusV1 {
    CurrentDeviceStatusV1 {
        schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
        issuer: value.issuer.clone(),
        audience: value.audience.clone(),
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        device_id: value.device_id.clone(),
        device_proof_key_ref: value.device_proof_key_ref.clone(),
        session_ref: value.session_ref.clone(),
        device_posture: value.device_posture.clone(),
        revocation_epochs: value.revocation_epochs.clone(),
        issued_at_epoch_s: value.issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
        nonce: value.nonce.clone(),
        key_id: "status-key".into(),
        signature: String::new(),
    }
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
