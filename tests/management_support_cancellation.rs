use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::*;

pub fn response(request: &[u8], projection: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
    let request = decode_endpoint_revocation_execution_cancel_request_strict(request)
        .map_err(|_| AgentError::RequestInvalid)?;
    let projection =
        decode_management_projection_strict(projection).map_err(|_| AgentError::ResponseInvalid)?;
    let ManagementProjectionBodyV2::Operation { operation } = projection.body else {
        return Err(AgentError::ResponseInvalid);
    };
    let identity = match &request.cancel_envelope.evidence {
        EndpointManagementEvidenceV2::Cancel {
            identity_exchange, ..
        } => identity_evidence_from_exchange(identity_exchange)
            .map_err(|_| AgentError::ResponseInvalid)?,
        _ => return Err(AgentError::ResponseInvalid),
    };
    let begun = begun(&request)?;
    let pending = pending(&request, identity, begun)?;
    let revision = projection.snapshot_revision.saturating_add(1);
    let mut value = build(&request, identity, begun, pending, operation, revision, now)?;
    value.cancellation_id = endpoint_revocation_execution_cancellation_id(&value)
        .map_err(|_| AgentError::ResponseInvalid)?;
    value.token.proof_id.clone_from(&value.cancellation_id);
    value.token.binding_sha256 =
        command_digest(&value.cancel_pending_request).map_err(|_| AgentError::ResponseInvalid)?;
    value.token.signature = sign(
        9,
        &canonical_signed_evidence(&value.token).map_err(|_| AgentError::ResponseInvalid)?,
    );
    value.signature = sign(
        2,
        &canonical_endpoint_revocation_execution_cancellation(&value)
            .map_err(|_| AgentError::ResponseInvalid)?,
    );
    serde_json::to_vec(&value).map_err(|_| AgentError::ResponseInvalid)
}

fn begun(
    request: &EndpointRevocationExecutionCancelRequestV1,
) -> Result<&RevocationCeremonyMetadata, AgentError> {
    match &request.begin_exchange.response.outcome {
        ResponseOutcome::Committed {
            result: AuthorityResult::RevocationBegun(value),
        } => Ok(value),
        _ => Err(AgentError::ResponseInvalid),
    }
}

fn pending(
    request: &EndpointRevocationExecutionCancelRequestV1,
    identity: &IdentityEvidenceMetadata,
    begun: &RevocationCeremonyMetadata,
) -> Result<AuthorityRequestV1, AgentError> {
    Ok(AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command: AuthorityCommand::CancelPendingRevocation(CancelPendingRevocationCommand {
            command_id: request.request_id.clone(),
            finalize_command_id: request.operation_id.clone(),
            attempt_id: begun.attempt_id.clone(),
            opaque_owner_ref: request.prepared.opaque_owner_ref.clone(),
            service_id: identity.assertion.service_id.clone(),
            pairwise_subject: identity.assertion.pairwise_subject.clone(),
            source_device_id: request.prepared.source_device_ref.clone(),
            source_session_ref: request.prepared.source_session_ref.clone(),
            target_digest_sha256: begun.target_digest.clone(),
            begin_command_digest_sha256: command_digest(&request.begin_exchange.request)
                .map_err(|_| AgentError::ResponseInvalid)?,
            cancelled_state_revision: request.expected_cancelled_state_revision,
            authority_id: "revocation-reservation-key".into(),
        }),
        evidence: Vec::new(),
    })
}

include!("management_support_cancellation_build.rs");

fn sign(byte: u8, value: &[u8]) -> String {
    hex::encode(SigningKey::from_bytes(&[byte; 32]).sign(value).to_bytes())
}
