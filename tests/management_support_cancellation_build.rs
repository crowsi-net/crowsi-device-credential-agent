fn build(
    request: &EndpointRevocationExecutionCancelRequestV1,
    identity: &IdentityEvidenceMetadata,
    begun: &RevocationCeremonyMetadata,
    pending: AuthorityRequestV1,
    operation: ManagementOperationV2,
    revision: u64,
    now: u64,
) -> Result<EndpointRevocationExecutionCancellationV1, AgentError> {
    Ok(EndpointRevocationExecutionCancellationV1 {
        schema: ENDPOINT_REVOCATION_EXECUTION_CANCELLATION_SCHEMA.into(),
        cancellation_id: String::new(),
        cancellation_request_sha256: endpoint_revocation_execution_cancel_request_digest(request)
            .map_err(|_| AgentError::ResponseInvalid)?,
        cancel_envelope_digest_sha256: endpoint_revocation_cancel_envelope_digest(
            &request.cancel_envelope,
        )
        .map_err(|_| AgentError::ResponseInvalid)?,
        pre_final_acceptance_request_sha256: request.pre_final_acceptance_request_sha256.clone(),
        prepared_operation_digest_sha256: endpoint_operation_digest(&request.prepared)
            .map_err(|_| AgentError::ResponseInvalid)?,
        opaque_owner_ref: request.prepared.opaque_owner_ref.clone(),
        service_id: identity.assertion.service_id.clone(),
        pairwise_subject: identity.assertion.pairwise_subject.clone(),
        source_device_ref: request.prepared.source_device_ref.clone(),
        source_session_ref: request.prepared.source_session_ref.clone(),
        target_digest_sha256: begun.target_digest.clone(),
        begin_exchange_digest_sha256: endpoint_signed_authority_exchange_digest(
            &request.begin_exchange,
        )
        .map_err(|_| AgentError::ResponseInvalid)?,
        begin_command_digest_sha256: command_digest(&request.begin_exchange.request)
            .map_err(|_| AgentError::ResponseInvalid)?,
        finalize_command_id: request.operation_id.clone(),
        cancelled_state_revision: request.expected_cancelled_state_revision,
        execution_reservation_id: None,
        cancellation_config_generation: 1,
        cancellation_accepted_revision: revision,
        operation,
        snapshot_revision: revision,
        cancel_pending_request: pending,
        token: SignedEvidenceV1 {
            schema: SIGNED_EVIDENCE_SCHEMA.into(),
            role: VerificationRole::RevocationExecutionCancellation,
            proof_id: String::new(),
            key_id: "revocation-reservation-key".into(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now.saturating_add(120),
            binding_sha256: String::new(),
            signature: String::new(),
        },
        issuer: "crowsi-credential-authority".into(),
        audience: "endpoint-a".into(),
        config_generation: 1,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now.saturating_add(30),
        key_id: "management-key".into(),
        signature: String::new(),
    })
}
