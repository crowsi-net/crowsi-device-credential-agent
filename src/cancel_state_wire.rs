use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointPreparedLookupPhaseV1, ManagementCommandV2,
    ManagementOperationState, ManagementProjectionV2, decode_endpoint_management_envelope_strict,
    decode_endpoint_prepared_lookup_request_strict,
    decode_endpoint_prepared_lookup_response_strict, decode_management_projection_strict,
    endpoint_prepared_lookup_request_digest,
};

use crate::{AgentError, cancel_state_types::CancelRecordV1};

pub(super) fn exact(value: &CancelRecordV1) -> Result<(), AgentError> {
    crate::current_request_validation::exact(
        &value.current_request,
        value.current_exchange.as_ref().map(|item| &item.request),
    )?;
    lookup_request(value)?;
    lookup_response(value)?;
    envelope(value)?;
    response(value)?;
    crate::cancel_state_wire_projection::exact(value)?;
    crate::cancel_state_wire_revocation::exact(value)?;
    crate::cancel_state_wire_cleanup::exact(value)?;
    crate::cancel_state_wire_cleanup_complete::exact(value)
}

pub(super) fn response_value(
    value: &CancelRecordV1,
) -> Result<Option<ManagementProjectionV2>, AgentError> {
    if let Some(response) = &value.response {
        return Ok(Some(response.clone()));
    }
    value
        .response_json
        .as_deref()
        .map(|wire| {
            decode_management_projection_strict(wire.as_bytes())
                .map_err(|_| AgentError::AuthorityRollback)
        })
        .transpose()
}

fn lookup_request(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(request) = &value.lookup_request else {
        return Ok(());
    };
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_prepared_lookup_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let ManagementCommandV2::Cancel {
        operation_id,
        expected_state_revision,
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let exact = decoded == *request
        && request.phase == EndpointPreparedLookupPhaseV1::Cancel
        && request.operation_id == *operation_id
        && request.expected_state_revision == *expected_state_revision
        && value.current_exchange.as_ref() == Some(&request.identity_exchange);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn lookup_response(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(response) = value.lookup_response.as_ref() else {
        return Ok(());
    };
    let wire = serde_json::to_vec(response).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_prepared_lookup_response_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let request = value
        .lookup_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let digest = endpoint_prepared_lookup_request_digest(request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let identity = crowsi_credential_authority_contracts::identity_evidence_from_exchange(
        &request.identity_exchange,
    )
    .map_err(|_| AgentError::AuthorityRollback)?;
    let assertion = &identity.assertion;
    let epochs = &assertion.revocation_epochs;
    let eligible = matches!(
        decoded.operation.state,
        ManagementOperationState::AwaitingSourceUv
            | ManagementOperationState::AwaitingTarget
            | ManagementOperationState::AwaitingTargetUv
            | ManagementOperationState::AwaitingIndependentApproval
            | ManagementOperationState::AwaitingApprovalUv
            | ManagementOperationState::AwaitingRevocationFinal
    );
    let exact = decoded == *response
        && decoded.request_id == request.request_id
        && decoded.request_digest_sha256 == digest
        && decoded.operation.operation_id == value.operation_id
        && decoded.operation.state_revision == request.expected_state_revision
        && decoded.prepared.operation_id == value.operation_id
        && decoded.prepared.source_device_ref == assertion.device_id
        && decoded.actor_device_ref == assertion.device_id
        && decoded.actor_session_ref == assertion.session_ref
        && (
            decoded.subject_revocation_epoch,
            decoded.service_revocation_epoch,
            decoded.device_revocation_epoch,
            decoded.session_revocation_epoch,
        ) == (
            epochs.subject,
            epochs.service,
            epochs.device,
            epochs.session,
        )
        && eligible
        && (decoded.operation.state != ManagementOperationState::AwaitingRevocationFinal
            || decoded.prepared.source_session_ref == assertion.session_ref);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn envelope(value: &CancelRecordV1) -> Result<(), AgentError> {
    let Some(envelope) = value.central_envelope.as_ref() else {
        return Ok(());
    };
    let wire = serde_json::to_vec(envelope).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    if decoded != **envelope || decoded.browser_request != value.browser_request {
        return Err(AgentError::AuthorityRollback);
    }
    if let (Some(current), Some(lookup)) = (&value.current_exchange, &value.lookup_response) {
        let exact = matches!(&decoded.evidence, EndpointManagementEvidenceV2::Cancel {
            identity_exchange, prepared
        } if identity_exchange == current && prepared == &lookup.prepared);
        if !exact {
            return Err(AgentError::AuthorityRollback);
        }
    }
    Ok(())
}

fn response(value: &CancelRecordV1) -> Result<(), AgentError> {
    response_value(value).map(|_| ())
}
