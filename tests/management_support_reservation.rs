use crowsi_credential_authority_contracts::*;
use crowsi_device_credential_agent::AgentError;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    AuthorityResult, ResponseOutcome, SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole,
    canonical_signed_evidence, command_digest,
};

pub fn response(request: &[u8], pre_final: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
    let request = decode_endpoint_revocation_execution_reserve_request_strict(request)
        .map_err(|_| AgentError::RequestInvalid)?;
    let projection =
        decode_management_projection_strict(pre_final).map_err(|_| AgentError::ResponseInvalid)?;
    let ManagementProjectionBodyV2::Operation { mut operation } = projection.body else {
        return Err(AgentError::ResponseInvalid);
    };
    operation.state = ManagementOperationState::RevocationExecutionReserved;
    operation.state_revision = request
        .expected_state_revision
        .checked_add(1)
        .ok_or(AgentError::ResponseInvalid)?;
    operation.actor = reconcile_actor();
    operation.webauthn_options = None;
    operation.reason = None;
    let identity = identity_evidence_from_exchange(&request.accepted_identity_exchange)
        .map_err(|_| AgentError::ResponseInvalid)?;
    let mut value = build(
        &request,
        operation,
        identity,
        projection.snapshot_revision,
        now,
    )?;
    value.reservation_id = endpoint_revocation_execution_reservation_id(&value)
        .map_err(|_| AgentError::ResponseInvalid)?;
    value.token.proof_id.clone_from(&value.reservation_id);
    value
        .token
        .binding_sha256
        .clone_from(&value.final_command_digest_sha256);
    let token = canonical_signed_evidence(&value.token).map_err(|_| AgentError::ResponseInvalid)?;
    value.token.signature = sign(9, &token);
    let outer = canonical_endpoint_revocation_execution_reservation(&value)
        .map_err(|_| AgentError::ResponseInvalid)?;
    value.signature = sign(2, &outer);
    serde_json::to_vec(&value).map_err(|_| AgentError::ResponseInvalid)
}

fn build(
    request: &EndpointRevocationExecutionReserveRequestV1,
    operation: ManagementOperationV2,
    identity: &ihat_identity_assertion_contracts::IdentityEvidenceMetadata,
    snapshot: u64,
    now: u64,
) -> Result<EndpointRevocationExecutionReservationV1, AgentError> {
    let target = match &request.begin_exchange.response.outcome {
        ResponseOutcome::Committed {
            result: AuthorityResult::RevocationBegun(value),
        } => value.target_digest.clone(),
        _ => return Err(AgentError::ResponseInvalid),
    };
    Ok(EndpointRevocationExecutionReservationV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_RESERVATION_SCHEMA.into(),
        reservation_id: String::new(),
        reservation_request_sha256: endpoint_revocation_execution_reserve_request_digest(request)
            .map_err(|_| AgentError::ResponseInvalid)?,
        original_request_id: request.original_request.request_id.clone(),
        original_command_digest_sha256: management_command_digest(&request.original_request)
            .map_err(|_| AgentError::ResponseInvalid)?,
        prepared_operation_digest_sha256: endpoint_operation_digest(&request.prepared)
            .map_err(|_| AgentError::ResponseInvalid)?,
        reconcile_digest: request.reconcile_digest.clone(),
        opaque_owner_ref: request.prepared.opaque_owner_ref.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        source_device_ref: request.prepared.source_device_ref.clone(),
        finalizer_device_ref: identity.assertion.device_id.clone(),
        target_digest_sha256: target,
        begin_exchange_digest_sha256: endpoint_signed_authority_exchange_digest(
            &request.begin_exchange,
        )
        .map_err(|_| AgentError::ResponseInvalid)?,
        approval_exchange_digest_sha256: None,
        final_command_digest_sha256: command_digest(&request.final_revoke_request)
            .map_err(|_| AgentError::ResponseInvalid)?,
        pre_final_state_revision: request.expected_state_revision,
        reserved_state_revision: operation.state_revision,
        reservation_config_generation: 1,
        operation,
        snapshot_revision: snapshot.saturating_add(1),
        token: token(now),
        issuer: "crowsi-credential-authority".into(),
        audience: "endpoint-a".into(),
        config_generation: 1,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(30),
        key_id: "management-key".into(),
        signature: String::new(),
    })
}

fn token(now: u64) -> SignedEvidenceV1 {
    SignedEvidenceV1 {
        schema: SIGNED_EVIDENCE_SCHEMA.into(),
        role: VerificationRole::RevocationExecutionReservation,
        proof_id: String::new(),
        key_id: "revocation-reservation-key".into(),
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(120),
        binding_sha256: String::new(),
        signature: String::new(),
    }
}

fn reconcile_actor() -> ActorRequirementV2 {
    ActorRequirementV2 {
        role: RequiredActorRole::ReconcileOnly,
        required_actor_device_ref: None,
        required_approval_authority_ref: None,
        excluded_actor_device_refs: Vec::new(),
    }
}

fn sign(byte: u8, value: &[u8]) -> String {
    hex::encode(SigningKey::from_bytes(&[byte; 32]).sign(value).to_bytes())
}
