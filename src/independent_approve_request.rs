use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, SignedAuthorityExchangeV1, identity_evidence_from_exchange,
    revocation_approval_command_id,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, ApprovalRoleDto, ApproveRevocationCommand, AuthorityCommand,
    AuthorityEvidence, AuthorityRequestV1, command_digest, decode_authority_request_strict,
};

use crate::{AgentError, config::AgentConfigDocument};

pub(crate) fn build(
    config: &AgentConfigDocument,
    uid: u32,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    now: u64,
) -> Result<AuthorityRequestV1, AgentError> {
    let metadata = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?;
    let identity =
        identity_evidence_from_exchange(current).map_err(|_| AgentError::IdentityUnavailable)?;
    let actor = &identity.assertion.device_id;
    let authority = crate::independent_approve_request_context::authority(config, prepared, actor)?;
    let command_id =
        revocation_approval_command_id(prepared, actor).map_err(|_| AgentError::RequestInvalid)?;
    let fields = [
        prepared.operation_id.as_str(),
        metadata.attempt_id.as_str(),
        actor.as_str(),
        authority,
    ];
    let proof_id = crate::independent_approve_request_context::id("proof", &fields)?;
    let mut request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: crate::independent_approve_request_context::id("request", &fields)?,
        command: AuthorityCommand::ApproveRevocation(ApproveRevocationCommand {
            command_id,
            finalize_command_id: prepared.operation_id.clone(),
            attempt_id: metadata.attempt_id.clone(),
            approval_nonce: metadata
                .approval_nonce
                .clone()
                .ok_or(AgentError::AuthorityResponseInvalid)?,
            approval_proof_id: proof_id.clone(),
            approval_role: ApprovalRoleDto::RecoveryApproval,
            authority_id: authority.into(),
            approver_device_id: actor.clone(),
        }),
        evidence: Vec::new(),
    };
    let binding = command_digest(&request).map_err(|_| AgentError::RequestInvalid)?;
    let signer = crate::independent_approve_key::open(config, uid)?;
    request.evidence.push(AuthorityEvidence::Signed(
        signer.sign(&proof_id, &binding, now)?,
    ));
    crate::independent_approve_request_validation::current(
        &config.recovery_approval_key_id,
        &config.recovery_approval_public_key_hex,
        prepared,
        begun,
        current,
        &request,
        now,
    )?;
    strict(request)
}

fn strict(value: AuthorityRequestV1) -> Result<AuthorityRequestV1, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
