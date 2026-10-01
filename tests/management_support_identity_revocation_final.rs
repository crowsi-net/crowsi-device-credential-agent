pub fn final_request(
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
) -> Result<Option<AuthorityRequestV1>, AgentError> {
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(value),
    } = &begun.response.outcome
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let independent = prepared
        .revocation
        .as_ref()
        .is_some_and(|item| item.target_device_ref != prepared.source_device_ref);
    if independent {
        let exact = value.independent_approval_required
            && value.state == RevocationCeremonyStateDto::AwaitingIndependentApproval;
        return exact
            .then_some(None)
            .ok_or(AgentError::AuthorityResponseInvalid);
    }
    if value.independent_approval_required
        || value.state != RevocationCeremonyStateDto::ReadyToFinalize
    {
        return Err(AgentError::AuthorityResponseInvalid);
    }
    let requirements = prepared
        .revocation
        .as_ref()
        .ok_or(AgentError::RequestInvalid)?;
    let command = match &prepared.intent {
        ManagementIntentV2::DeviceRevocation {
            service_id,
            target_device_ref,
            expected_device_revocation_epoch,
            ..
        } => AuthorityCommand::RevokeDeviceByRef(RevokeDeviceByRefCommand {
            command_id: prepared.operation_id.clone(),
            service_id: service_id.clone(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            target_device_id: target_device_ref.clone(),
            expected_device_epoch: *expected_device_revocation_epoch,
            authority_id: requirements.finalization_authority_id.clone(),
        }),
        ManagementIntentV2::SessionRevocation {
            service_id,
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => AuthorityCommand::RevokeSessionByRef(RevokeSessionByRefCommand {
            command_id: prepared.operation_id.clone(),
            service_id: service_id.clone(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            session_ref: target_session_ref.clone(),
            expected_epoch: *expected_session_revocation_epoch,
            authority_id: requirements.finalization_authority_id.clone(),
        }),
        ManagementIntentV2::DeviceTransfer { .. } => return Err(AgentError::RequestInvalid),
    };
    Ok(Some(AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: "revocation-final-request".into(),
        command,
        evidence: Vec::new(),
    }))
}

pub fn final_exchange(
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
    now: u64,
    substitute: bool,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let ResponseOutcome::Committed {
        result: AuthorityResult::RevocationBegun(ceremony),
    } = &begun.response.outcome
    else {
        return Err(AgentError::AuthorityResponseInvalid);
    };
    let target = if substitute {
        "99".repeat(32)
    } else {
        ceremony.target_digest.clone()
    };
    let result = match &prepared.intent {
        ManagementIntentV2::DeviceRevocation {
            expected_device_revocation_epoch,
            ..
        } => AuthorityResult::DeviceRevocation(DeviceRevocationMetadata {
            target_digest: target,
            previous_device_epoch: *expected_device_revocation_epoch,
            current_device_epoch: expected_device_revocation_epoch + 1,
            revoked_session_count: prepared
                .revocation
                .as_ref()
                .and_then(|item| item.expected_revoked_session_count)
                .ok_or(AgentError::RequestInvalid)?,
            audit_sequence: 9,
        }),
        ManagementIntentV2::SessionRevocation {
            expected_session_revocation_epoch,
            ..
        } => AuthorityResult::Revocation(RevocationMetadata {
            target_digest: target,
            previous_epoch: *expected_session_revocation_epoch,
            current_epoch: expected_session_revocation_epoch + 1,
            audit_sequence: 10,
        }),
        ManagementIntentV2::DeviceTransfer { .. } => return Err(AgentError::RequestInvalid),
    };
    signed_final(request, result, now)
}

fn signed_final(
    request: &AuthorityRequestV1,
    result: AuthorityResult,
    now: u64,
) -> Result<SignedAuthorityExchangeV1, AgentError> {
    let mut response = AuthorityResponseV1 {
        schema: AUTHORITY_RESPONSE_SCHEMA.into(),
        request_id: request.request_id.clone(),
        command_type: request.command.type_name().into(),
        command_digest: command_digest(request).map_err(|_| AgentError::RequestInvalid)?,
        config_generation: 1,
        issued_at_epoch_s: now,
        expires_at_epoch_s: now + 15,
        outcome: ResponseOutcome::Committed { result },
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
