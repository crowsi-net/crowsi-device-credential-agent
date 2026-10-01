use ihat_identity_assertion_contracts::{
    AuthorityCommand, AuthorityEvidence, AuthorityRequestV1, VerificationRole, command_digest,
    decode_authority_request_strict,
};

use crate::AgentError;

pub(crate) fn exact(
    request: &AuthorityRequestV1,
    response_request: Option<&AuthorityRequestV1>,
) -> Result<(), AgentError> {
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded =
        decode_authority_request_strict(&wire).map_err(|_| AgentError::AuthorityRollback)?;
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) = &request.command else {
        return Err(AgentError::AuthorityRollback);
    };
    let [AuthorityEvidence::Signed(proof)] = request.evidence.as_slice() else {
        return Err(AgentError::AuthorityRollback);
    };
    let exact = decoded == *request
        && proof.role == VerificationRole::SessionSender
        && proof.proof_id == command.session_sender_proof_id
        && proof.binding_sha256
            == command_digest(request).map_err(|_| AgentError::AuthorityRollback)?
        && response_request.is_none_or(|value| value == request);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
