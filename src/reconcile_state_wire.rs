use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, EndpointPreparedLookupPhaseV1, ManagementCommandV2,
    ManagementOperationState, RequiredActorRole, decode_endpoint_management_envelope_strict,
    decode_endpoint_prepared_lookup_request_strict,
    decode_endpoint_prepared_lookup_response_strict, decode_management_projection_strict,
    endpoint_prepared_lookup_request_digest, identity_evidence_from_exchange,
};

use crate::{AgentError, reconcile_state_types::ReconcileRecordV1};

pub(super) fn exact(value: &ReconcileRecordV1) -> Result<(), AgentError> {
    crate::current_request_validation::exact(
        &value.current_request,
        value.current_exchange.as_ref().map(|item| &item.request),
    )?;
    lookup_request(value)?;
    lookup_response(value)?;
    envelope(value)?;
    response(value)
}

fn lookup_request(value: &ReconcileRecordV1) -> Result<(), AgentError> {
    let Some(request) = &value.lookup_request else {
        return Ok(());
    };
    let wire = serde_json::to_vec(request).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_prepared_lookup_request_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let ManagementCommandV2::Reconcile {
        operation_id,
        expected_state_revision,
        ..
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let exact = decoded == *request
        && request.phase == EndpointPreparedLookupPhaseV1::Reconcile
        && request.operation_id == *operation_id
        && request.expected_state_revision == *expected_state_revision
        && value.current_exchange.as_ref() == Some(&request.identity_exchange);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn lookup_response(value: &ReconcileRecordV1) -> Result<(), AgentError> {
    let Some(wire) = value.lookup_response_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_endpoint_prepared_lookup_response_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let request = value
        .lookup_request
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let identity = identity_evidence_from_exchange(&request.identity_exchange)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let epochs = &identity.assertion.revocation_epochs;
    let ManagementCommandV2::Reconcile {
        reconcile_digest, ..
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    let exact = value.lookup_response.as_ref() == Some(&decoded)
        && decoded.request_id == request.request_id
        && decoded.request_digest_sha256
            == endpoint_prepared_lookup_request_digest(request)
                .map_err(|_| AgentError::AuthorityRollback)?
        && decoded.operation.operation_id == value.operation_id
        && decoded.operation.state_revision == request.expected_state_revision
        && decoded.operation.state == ManagementOperationState::Unknown
        && decoded.operation.actor.role == RequiredActorRole::ReconcileOnly
        && decoded.operation.reconcile_digest.as_ref() == Some(reconcile_digest)
        && decoded.prepared.operation_id == value.operation_id
        && decoded.actor_device_ref == identity.assertion.device_id
        && decoded.actor_session_ref == identity.assertion.session_ref
        && (
            decoded.subject_revocation_epoch,
            decoded.service_revocation_epoch,
        ) == (epochs.subject, epochs.service)
        && (
            decoded.device_revocation_epoch,
            decoded.session_revocation_epoch,
        ) == (epochs.device, epochs.session);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn envelope(value: &ReconcileRecordV1) -> Result<(), AgentError> {
    let Some(wire) = value.central_envelope_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_endpoint_management_envelope_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let prepared = value
        .lookup_response
        .as_ref()
        .map(|item| &item.prepared)
        .ok_or(AgentError::AuthorityRollback)?;
    let exact = value.central_envelope.as_ref() == Some(&decoded)
        && decoded.browser_request == value.browser_request
        && matches!(&decoded.evidence, EndpointManagementEvidenceV2::Reconcile {
            identity_exchange, prepared: sent
        } if Some(identity_exchange) == value.current_exchange.as_ref() && sent == prepared);
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn response(value: &ReconcileRecordV1) -> Result<(), AgentError> {
    let Some(wire) = value.response_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    (value.response.as_ref() == Some(&decoded))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
