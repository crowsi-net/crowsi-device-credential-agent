use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1, identity_evidence_from_exchange,
    revocation_approval_command_id,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, ApprovalRoleDto, AuthorityCommand, AuthorityEvidence,
    AuthorityRequestV1, SignedEvidenceBinding, VerificationRole, command_digest,
    verify_signed_evidence_at,
};

use crate::AgentError;

pub(crate) fn current(
    key_id: &str,
    public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
    now: u64,
) -> Result<(), AgentError> {
    let proof = exact(key_id, prepared, begun, current, request)?;
    let binding = command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
    verify_signed_evidence_at(
        proof,
        &SignedEvidenceBinding {
            role: VerificationRole::RecoveryApproval,
            proof_id: &proof.proof_id,
            binding_sha256: &binding,
        },
        key_id,
        public_key_hex,
        now,
    )
    .map_err(|_| AgentError::RequestInvalid)
}

pub(crate) fn historic(
    key_id: &str,
    public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
) -> Result<(), AgentError> {
    let proof = exact(key_id, prepared, begun, current, request)?;
    let payload = ihat_identity_assertion_contracts::canonical_signed_evidence(proof)
        .map_err(|_| AgentError::RequestInvalid)?;
    crate::crypto::verify_hex(public_key_hex, &proof.signature, &payload)
        .then_some(())
        .ok_or(AgentError::RequestInvalid)
}

fn exact<'a>(
    key_id: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    request: &'a AuthorityRequestV1,
) -> Result<&'a ihat_identity_assertion_contracts::SignedEvidenceV1, AgentError> {
    let metadata = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?;
    let identity =
        identity_evidence_from_exchange(current).map_err(|_| AgentError::IdentityUnavailable)?;
    let actor = &identity.assertion.device_id;
    let authority = crate::independent_approve_request_context::required(prepared, actor)?;
    let fields = [
        prepared.operation_id.as_str(),
        metadata.attempt_id.as_str(),
        actor,
        authority,
    ];
    let [AuthorityEvidence::Signed(proof)] = request.evidence.as_slice() else {
        return Err(AgentError::RequestInvalid);
    };
    let AuthorityCommand::ApproveRevocation(command) = &request.command else {
        return Err(AgentError::RequestInvalid);
    };
    let binding = command_digest(request).map_err(|_| AgentError::RequestInvalid)?;
    let command_id =
        revocation_approval_command_id(prepared, actor).map_err(|_| AgentError::RequestInvalid)?;
    let exact = request.schema == AUTHORITY_REQUEST_SCHEMA
        && request.request_id
            == crate::independent_approve_request_context::id("request", &fields)?
        && command.command_id == command_id
        && command.finalize_command_id == prepared.operation_id
        && command.attempt_id == metadata.attempt_id
        && metadata.approval_nonce.as_ref() == Some(&command.approval_nonce)
        && command.approval_proof_id == proof.proof_id
        && command.approval_role == ApprovalRoleDto::RecoveryApproval
        && command.authority_id == authority
        && command.approver_device_id == *actor
        && proof.proof_id == crate::independent_approve_request_context::id("proof", &fields)?
        && proof.role == VerificationRole::RecoveryApproval
        && proof.key_id == key_id
        && proof.binding_sha256 == binding
        && proof
            .expires_at_epoch_s
            .checked_sub(proof.issued_at_epoch_s)
            == Some(15)
        && begun.response.issued_at_epoch_s <= proof.issued_at_epoch_s
        && proof.issued_at_epoch_s < metadata.expires_at_epoch_s;
    exact.then_some(proof).ok_or(AgentError::RequestInvalid)
}
