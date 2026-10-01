use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, revocation_begin_command_id,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityEvidence, AuthorityRequestV1,
    FreshAuthenticationDto, FreshUvV1, SignedEvidenceV1, VerificationRole, command_digest,
    decode_authority_request_strict,
};

use crate::{AgentError, session_sender::SessionSender};

pub(crate) trait SessionProofSigner {
    fn sign_session_proof(
        &self,
        proof_id: &str,
        binding_sha256: &str,
        now: u64,
    ) -> Result<SignedEvidenceV1, AgentError>;
}

impl SessionProofSigner for SessionSender {
    fn sign_session_proof(
        &self,
        proof_id: &str,
        binding_sha256: &str,
        now: u64,
    ) -> Result<SignedEvidenceV1, AgentError> {
        self.sign(proof_id, binding_sha256, now)
    }
}

pub(crate) fn begin<S: SessionProofSigner>(
    signer: &S,
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    now: u64,
) -> Result<AuthorityRequestV1, AgentError> {
    crate::source_approve_revocation_binding::requirements(prepared)?;
    crate::source_approve_revocation_binding::fresh(prepared, fresh, now)?;
    let proof_id = crate::random_id::create("revocation-sender-proof")?;
    let command_id =
        revocation_begin_command_id(prepared).map_err(|_| AgentError::RequestInvalid)?;
    let command = crate::source_approve_revocation_begin_command::build(
        prepared,
        command_id,
        proof_id.clone(),
        authentication(fresh),
    )?;
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: crate::random_id::create("revocation-begin-request")?,
        command,
        evidence: vec![AuthorityEvidence::FreshUv(fresh.clone())],
    };
    let binding = command_digest(&request).map_err(|_| AgentError::RequestInvalid)?;
    let sender = signer.sign_session_proof(&proof_id, &binding, now)?;
    request.evidence.push(AuthorityEvidence::Signed(sender));
    validate_begin(prepared, fresh, &request, now)?;
    strict(request)
}

pub(crate) fn validate_begin(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<(), AgentError> {
    crate::source_approve_revocation_binding::requirements(prepared)?;
    crate::source_approve_revocation_binding::fresh(prepared, fresh, now)?;
    let expected_id =
        revocation_begin_command_id(prepared).map_err(|_| AgentError::RequestInvalid)?;
    let binding = command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
    let [
        AuthorityEvidence::FreshUv(observed),
        AuthorityEvidence::Signed(sender),
    ] = request.evidence.as_slice()
    else {
        return Err(AgentError::RequestInvalid);
    };
    let exact = observed == fresh
        && sender.role == VerificationRole::SessionSender
        && sender.proof_id == sender_id(&request.command)?
        && distinct_ids(prepared, fresh, sender, &expected_id)
        && sender.binding_sha256 == binding
        && sender.key_id != fresh.key_id
        && sender.issued_at_epoch_s <= now
        && now < sender.expires_at_epoch_s
        && crate::source_approve_revocation_begin_exact::matches(
            prepared,
            fresh,
            &request.command,
            &expected_id,
        );
    exact.then_some(()).ok_or(AgentError::RequestInvalid)
}

fn distinct_ids(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    sender: &SignedEvidenceV1,
    command_id: &str,
) -> bool {
    command_id != fresh.proof_id
        && command_id != sender.proof_id
        && fresh.proof_id != sender.proof_id
        && prepared.source_identity_nonce != command_id
        && prepared.source_identity_nonce != fresh.proof_id
        && prepared.source_identity_nonce != sender.proof_id
}

pub(crate) fn authentication(value: &FreshUvV1) -> FreshAuthenticationDto {
    FreshAuthenticationDto {
        proof_id: value.proof_id.clone(),
        authenticator_id: value.credential_id.clone(),
        authenticator_key_fingerprint: value.authenticator_key_fingerprint.clone(),
        kind: value.kind,
        user_verified: value.user_verified,
        issued_at_epoch_s: value.issued_at_epoch_s,
        expires_at_epoch_s: value.expires_at_epoch_s,
        service_id: value.service_id.clone(),
        pairwise_subject: value.pairwise_subject.clone(),
        session_ref: value.session_ref.clone(),
        operation_digest_sha256: value.operation_digest_sha256.clone(),
        subject_epoch: value.subject_epoch,
        service_epoch: value.service_epoch,
        device_epoch: value.device_epoch,
        session_epoch: value.session_epoch,
    }
}

fn sender_id(value: &AuthorityCommand) -> Result<&str, AgentError> {
    match value {
        AuthorityCommand::BeginDeviceRevocation(value) => Ok(&value.sender_proof_id),
        AuthorityCommand::BeginSessionRevocation(value) => Ok(&value.sender_proof_id),
        _ => Err(AgentError::RequestInvalid),
    }
}

fn strict(value: AuthorityRequestV1) -> Result<AuthorityRequestV1, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
