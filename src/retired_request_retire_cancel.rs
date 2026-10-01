use crate::{
    AgentError,
    cancel_state_types::CancelRecordV1,
    retired_request_types::{
        RetiredCancelCleanupCompleteV1, RetiredCancelEnvelopeV1, RetiredRefreshMaterialV1,
        RetiredRequestReceiptV1,
    },
    source_options_state_types::OperationJournalV1,
};
use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, ManagementOperationState, ManagementProjectionBodyV2,
    decode_endpoint_management_envelope_strict,
    decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict,
    endpoint_revocation_cancellation_acknowledgement_result_digest,
    endpoint_revocation_execution_cancel_cleanup_complete_request_digest,
    management_command_digest,
};
pub(super) fn retire(
    journal: &mut OperationJournalV1,
    record: &CancelRecordV1,
    now: u64,
) -> Result<(), AgentError> {
    let envelope = record
        .central_envelope
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    let body = record
        .cancelled_projection_body
        .as_ref()
        .ok_or(AgentError::AuthorityRollback)?;
    exact(record, envelope, body)?;
    let wire = serde_json::to_vec(envelope).map_err(|_| AgentError::AuthorityRollback)?;
    let wire = String::from_utf8(wire).map_err(|_| AgentError::AuthorityRollback)?;
    let material = match record.cleanup_complete_response.as_ref() {
        Some(delivery) => {
            let request = record
                .cleanup_complete_request
                .as_ref()
                .ok_or(AgentError::AuthorityRollback)?;
            let request_digest =
                endpoint_revocation_execution_cancel_cleanup_complete_request_digest(request)
                    .map_err(|_| AgentError::AuthorityRollback)?;
            let result_digest =
                endpoint_revocation_cancellation_acknowledgement_result_digest(request)
                    .map_err(|_| AgentError::AuthorityRollback)?;
            delivery_exact(record, body, delivery, &request_digest, &result_digest)?;
            RetiredRefreshMaterialV1::CancelCleanupComplete(RetiredCancelCleanupCompleteV1 {
                wire,
                expected_body: body.clone(),
                cleanup_complete_request_sha256: request_digest,
                acknowledge_result_digest_sha256: result_digest,
                delivery: delivery.clone(),
            })
        }
        None => RetiredRefreshMaterialV1::CancelEnvelope(RetiredCancelEnvelopeV1 {
            wire,
            expected_body: body.clone(),
        }),
    };
    insert(journal, record, material, now)
}
fn exact(
    record: &CancelRecordV1,
    envelope: &crowsi_credential_authority_contracts::EndpointManagementEnvelopeV2,
    body: &ManagementProjectionBodyV2,
) -> Result<(), AgentError> {
    let wire = serde_json::to_vec(envelope).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_management_envelope_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let EndpointManagementEvidenceV2::Cancel { prepared, .. } = &decoded.evidence else {
        return Err(AgentError::AuthorityRollback);
    };
    let ManagementProjectionBodyV2::Operation { operation } = body else {
        return Err(AgentError::AuthorityRollback);
    };
    let valid = decoded == *envelope
        && decoded.browser_request == record.browser_request
        && prepared.operation_id == record.operation_id
        && operation.operation_id == record.operation_id
        && operation.state == ManagementOperationState::Cancelled;
    valid.then_some(()).ok_or(AgentError::AuthorityRollback)
}
fn delivery_exact(
    record: &CancelRecordV1,
    body: &ManagementProjectionBodyV2,
    delivery: &crowsi_credential_authority_contracts::EndpointRevocationExecutionCancellationCleanupCompleteV1,
    request_digest: &str,
    result_digest: &str,
) -> Result<(), AgentError> {
    let wire = serde_json::to_vec(delivery).map_err(|_| AgentError::AuthorityRollback)?;
    let decoded = decode_endpoint_revocation_execution_cancellation_cleanup_complete_strict(&wire)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let ManagementProjectionBodyV2::Operation { operation } = body else {
        return Err(AgentError::AuthorityRollback);
    };
    let valid = decoded == *delivery
        && decoded.operation == *operation
        && decoded.operation.operation_id == record.operation_id
        && decoded.cleanup_complete_request_sha256 == request_digest
        && decoded.acknowledge_result_digest_sha256 == result_digest
        && decoded.token.binding_sha256 == request_digest
        && record
            .central_envelope
            .as_ref()
            .and_then(|envelope| match &envelope.evidence {
                EndpointManagementEvidenceV2::Cancel { prepared, .. } => {
                    Some(prepared.source_device_ref.as_str())
                }
                _ => None,
            })
            == Some(decoded.source_device_ref.as_str())
        && decoded.token.proof_id == decoded.cleanup_complete_id;
    valid.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn insert(
    journal: &mut OperationJournalV1,
    record: &CancelRecordV1,
    material: RetiredRefreshMaterialV1,
    now: u64,
) -> Result<(), AgentError> {
    let retain = now.checked_add(600).ok_or(AgentError::AuthorityRollback)?;
    let value = RetiredRequestReceiptV1 {
        browser_request_digest_sha256: management_command_digest(&record.browser_request)
            .map_err(|_| AgentError::AuthorityRollback)?,
        operation_id: record.operation_id.clone(),
        route: "cancel".into(),
        refresh_material: Some(material.clone()),
        response_json: None,
        response: None,
        refresh_until_epoch_s: retain,
        retired_at_epoch_s: now,
        retain_until_epoch_s: retain,
    };
    if journal
        .retired_request_receipts
        .insert(record.browser_request.request_id.clone(), value)
        .is_some()
    {
        return Err(AgentError::AuthorityRollback);
    }
    crate::retired_request_bound::protected(journal, Some(&record.browser_request.request_id))?;
    journal
        .retired_request_receipts
        .get(&record.browser_request.request_id)
        .is_some_and(|value| value.refresh_material.as_ref() == Some(&material))
        .then_some(())
        .ok_or(AgentError::AuthorityUnavailable)
}
