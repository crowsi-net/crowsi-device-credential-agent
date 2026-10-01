use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;
use sha2::{Digest, Sha256};

use crate::management_support::{NOW, SESSION};

pub fn exchange() -> SignedAuthorityExchangeV1 {
    let identity = identity();
    let proof_id = "session-sender-proof";
    let sender_public = key(7).verifying_key().to_bytes();
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "identity-request".into(),
        command: AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
            IssueCurrentDeviceIdentityEvidenceCommand {
                service_id: "service-a".into(),
                pairwise_subject: "psu_pairwise-a".into(),
                device_id: "device-a".into(),
                audience: "crowsi-management".into(),
                identity_nonce: identity.assertion.nonce.clone(),
                ttl_seconds: 30,
                session_sender_key_fingerprint: hex::encode(Sha256::digest(sender_public)),
                session_sender_proof_id: proof_id.into(),
            },
        ),
        evidence: Vec::new(),
    };
    let digest = command_digest(&request).expect("command digest");
    request
        .evidence
        .push(AuthorityEvidence::Signed(signed_sender(proof_id, &digest)));
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: digest,
        config_generation: 1,
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 29,
        outcome: ResponseOutcome::Committed {
            result: AuthorityResult::IdentityEvidence(identity),
        },
        key_id: "authority-response-key".into(),
        signature: String::new(),
    };
    response.signature = hex::encode(
        key(3)
            .sign(&canonical_response(&response).expect("response"))
            .to_bytes(),
    );
    SignedAuthorityExchangeV1 { request, response }
}

fn identity() -> IdentityEvidenceMetadata {
    let mut assertion = DeviceIdentityAssertionV1 {
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
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 29,
        nonce: "identity-nonce".into(),
        key_id: "identity-key".into(),
        signature: String::new(),
    };
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
    IdentityEvidenceMetadata {
        assertion,
        current_status: status,
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

fn signed_sender(id: &str, digest: &str) -> SignedEvidenceV1 {
    let mut value = SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: id.into(),
        key_id: "session-sender-key".into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 14,
        binding_sha256: digest.into(),
        signature: String::new(),
    };
    value.signature = hex::encode(
        key(7)
            .sign(&canonical_signed_evidence(&value).expect("sender"))
            .to_bytes(),
    );
    value
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}
