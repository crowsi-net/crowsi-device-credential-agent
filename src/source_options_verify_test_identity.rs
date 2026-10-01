use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityEvidence, AuthorityRequestV1,
    AuthorityResult, IssueCurrentDeviceIdentityEvidenceCommand, SIGNED_EVIDENCE_SCHEMA,
    SignedEvidenceV1, VerificationRole, command_digest,
};

use super::{NOW, response};

pub(super) fn exchange() -> SignedAuthorityExchangeV1 {
    let identity = crate::prepared_operation_test_support::identity();
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "identity-request".into(),
        command: AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
            IssueCurrentDeviceIdentityEvidenceCommand {
                service_id: identity.assertion.service_id.clone(),
                pairwise_subject: identity.assertion.pairwise_subject.clone(),
                device_id: identity.assertion.device_id.clone(),
                audience: identity.assertion.audience.clone(),
                identity_nonce: identity.assertion.nonce.clone(),
                ttl_seconds: 30,
                session_sender_key_fingerprint: "11".repeat(32),
                session_sender_proof_id: "sender-proof".into(),
            },
        ),
        evidence: Vec::new(),
    };
    let digest = command_digest(&request).expect("identity digest");
    request
        .evidence
        .push(AuthorityEvidence::Signed(sender(&digest)));
    SignedAuthorityExchangeV1 {
        response: response(
            &request,
            AuthorityResult::IdentityEvidence(identity),
            NOW - 1,
            NOW + 29,
        ),
        request,
    }
}

fn sender(binding: &str) -> SignedEvidenceV1 {
    SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::SessionSender,
        proof_id: "sender-proof".into(),
        key_id: "sender-key".into(),
        issued_at_epoch_s: NOW - 1,
        expires_at_epoch_s: NOW + 15,
        binding_sha256: binding.into(),
        signature: "33".repeat(64),
    }
}
